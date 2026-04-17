from flask import Flask, request, jsonify
import webrtcvad
import numpy as np
import sherpa_onnx
import logging
import os
import time
import threading
import requests as http_requests

app = Flask(__name__)

# ── Loki log handler ──────────────────────────────────────────────────────────

class LokiHandler(logging.Handler):
    """Batches log entries and pushes to Loki every flush_interval seconds."""

    def __init__(self, url, labels, flush_interval=2.0, batch_size=50):
        super().__init__()
        self.url = url
        self.labels = labels
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        self._buffer = []
        self._lock = threading.Lock()
        self._start_flusher()

    def _start_flusher(self):
        def loop():
            while True:
                time.sleep(self.flush_interval)
                self._flush()
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def emit(self, record):
        try:
            ts = str(int(record.created * 1e9))
            line = self.format(record)
            with self._lock:
                self._buffer.append((ts, line, record.levelname))
                if len(self._buffer) >= self.batch_size:
                    self._flush_locked()
        except Exception:
            self.handleError(record)

    def _flush(self):
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        if not self._buffer:
            return
        buf = self._buffer
        self._buffer = []

        # Group by level
        by_level = {}
        for ts, line, level in buf:
            by_level.setdefault(level.lower(), []).append([ts, line])

        streams = []
        for level, values in by_level.items():
            labels = dict(self.labels)
            labels["level"] = level
            streams.append({"stream": labels, "values": values})

        try:
            http_requests.post(
                self.url,
                json={"streams": streams},
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
        except Exception as e:
            # Print to stderr so we don't recurse
            import sys
            print(f"loki push failed: {e}", file=sys.stderr)


def setup_logging():
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Stdout handler
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    root.addHandler(sh)

    # Loki handler (if configured)
    loki_url = os.environ.get("LOKI_URL")
    if loki_url:
        lh = LokiHandler(
            url=loki_url,
            labels={"job": "toucan-calls", "service": "vad"},
            flush_interval=2.0,
        )
        lh.setFormatter(formatter)
        root.addHandler(lh)
        logging.info("Loki logging enabled -> %s", loki_url)
    else:
        logging.info("LOKI_URL not set, logging to stdout only")

    # Quieten Flask/werkzeug request logs (they're noisy with per-frame VAD calls)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


setup_logging()
log = logging.getLogger("vad")

# ── VAD ───────────────────────────────────────────────────────────────────────

vad = webrtcvad.Vad(3)  # Aggressiveness mode (0-3)
log.info("WebRTC VAD initialized (aggressiveness=3)")

# ── Sherpa-ONNX Diarization ──────────────────────────────────────────────────

config = sherpa_onnx.OfflineSpeakerDiarizationConfig(
    segmentation=sherpa_onnx.OfflineSpeakerSegmentationModelConfig(
        pyannote=sherpa_onnx.OfflineSpeakerSegmentationPyannoteModelConfig(
            model="./sherpa-onnx-pyannote-segmentation-3-0/model.onnx",
        )
    ),
    embedding=sherpa_onnx.SpeakerEmbeddingExtractorConfig(
        model="./3dspeaker_speech_eres2net_sv_en_voxceleb_16k.onnx",
    ),
    clustering=sherpa_onnx.FastClusteringConfig(
        num_clusters=-1,
        threshold=0.5,
    ),
)
sd = sherpa_onnx.OfflineSpeakerDiarization(config)
log.info("Sherpa-ONNX diarization models loaded")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/vad', methods=['POST'])
def perform_vad():
    audio_data = request.data
    if not audio_data:
        return jsonify({'error': 'No audio data received'}), 400

    sample_rate = 16000

    try:
        is_speech = vad.is_speech(audio_data, sample_rate)
        return jsonify({'is_speech': is_speech})
    except Exception as e:
        log.warning("VAD processing error: %s", e)
        return jsonify({'error': str(e)}), 500


# Rolling buffer for diarization
audio_buffer = np.array([], dtype=np.float32)
MAX_BUFFER_SECONDS = 10
SAMPLE_RATE = 16000

@app.route('/diarize', methods=['POST'])
def perform_diarization():
    global audio_buffer
    audio_data = request.data
    if not audio_data:
        return jsonify({'error': 'No audio data received'}), 400

    try:
        samples = np.frombuffer(audio_data, dtype=np.int16).astype(np.float32) / 32768.0

        audio_buffer = np.concatenate((audio_buffer, samples))

        max_samples = MAX_BUFFER_SECONDS * SAMPLE_RATE
        if len(audio_buffer) > max_samples:
            audio_buffer = audio_buffer[-max_samples:]

        result = sd.process(audio_buffer, sample_rate=SAMPLE_RATE)

        output = []
        for r in result:
            output.append({
                "speaker": r.speaker,
                "start": r.start,
                "end": r.end
            })

        if output:
            log.info("Diarization: %d speakers detected", len(set(s["speaker"] for s in output)))

        return jsonify(output)
    except Exception as e:
        log.warning("Diarization error: %s", e)
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    log.info("Starting VAD service on port 5001")
    app.run(host='0.0.0.0', port=5001, debug=False)
