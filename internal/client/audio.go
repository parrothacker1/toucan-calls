package client

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gen2brain/malgo"
	"github.com/toucan/toucan-calls/internal/audio"
	"github.com/toucan/toucan-calls/internal/utils/codec"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (c *Client) InitAudioContext() error {
	ctx, err := malgo.InitContext(nil, malgo.ContextConfig{}, nil)
	if err != nil {
		return err
	}
	c.AudioCtx = ctx
	return nil
}

func (c *Client) InitPlaybackDevice() *malgo.Device {
	cfg := malgo.DefaultDeviceConfig(malgo.Playback)
	cfg.Playback.Format = malgo.FormatS16
	cfg.Playback.Channels = uint32(values.ClientchannelCount)
	cfg.SampleRate = uint32(values.ClientRate)
	cfg.Alsa.NoMMap = 1
	onSamples := func(out, _ []byte, framecount uint32) {
		select {
		case chunk := <-c.playbackBuf:
			copy(out, Int16SliceToBytes(chunk))
		default:
			for i := range out {
				out[i] = 0
			}
		}
	}
	deviceCallbacks := malgo.DeviceCallbacks{
		Data: onSamples,
	}
	device, err := malgo.InitDevice(c.AudioCtx.Context, cfg, deviceCallbacks)
	if err != nil {
		c.Log.Fatalf("playback device init failed: %v", err)
	}
	return device
}

func (c *Client) ProcessCapture() {
	c.Log.Info("capture processing loop started")

	// Create an HTTP client
	httpClient := &http.Client{
		Timeout: time.Second * 1,
	}

	// VAD backoff: suppress requests for 5s after a failure to avoid log spam
	var vadUnavailable atomic.Bool

	packet := make([]byte, 1024)
	for {
		var samples []int16
		select {
		case <-c.done:
			c.Log.Info("capture processing stopped (connection closed)")
			return
		case s, ok := <-c.captureChan:
			if !ok {
				return
			}
			samples = s
		}
		// Call the ML server (VAD or Diarization) — skip if service is down
		if !vadUnavailable.Load() {
			go func(samples []int16, model string, vadBase string) {
				byteSamples := Int16SliceToBytes(samples)

				endpoint := vadBase + "/vad"
				if model == "ml" {
					endpoint = vadBase + "/diarize"
				}

				resp, err := httpClient.Post(endpoint, "application/octet-stream", bytes.NewReader(byteSamples))
				if err != nil {
					if !vadUnavailable.Load() {
						c.Log.Warnf("ML service unavailable (%s), suppressing for 5s: %v", model, err)
						vadUnavailable.Store(true)
						go func() {
							time.Sleep(5 * time.Second)
							vadUnavailable.Store(false)
							c.Log.Info("retrying ML service connection")
						}()
					}
					return
				}
				defer resp.Body.Close()

				if model == "vad" {
					var vadResult struct {
						IsSpeech bool `json:"is_speech"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&vadResult); err != nil {
						c.Log.Warnf("vad response parse failed: %v", err)
						return
					}

					if vadResult.IsSpeech {
						c.Log.Info("VAD: Speech detected")
					} else {
						c.Log.Debug("VAD: Silence")
					}

					isSpeech := vadResult.IsSpeech
					c.SendUIEvent(WSEvent{
						Type:     "VAD_RESULT",
						IsSpeech: &isSpeech,
					})
				} else {
					var diarizeResult []struct {
						Speaker string  `json:"speaker"`
						Start   float64 `json:"start"`
						End     float64 `json:"end"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&diarizeResult); err != nil {
						c.Log.Warnf("diarization response parse failed: %v", err)
						return
					}

					if len(diarizeResult) > 0 {
						speakerList := []string{}
						for _, r := range diarizeResult {
							speakerList = append(speakerList, r.Speaker)
						}
						c.Log.Infof("Diarization: Speakers detected: %v", speakerList)

						c.SendUIEvent(WSEvent{
							Type:     "SPEAKER_DETECTED",
							Speakers: speakerList,
						})
					}
				}
			}(samples, c.Model, c.VadURL)
		}


		n, err := codec.OpusEncoder.Encode(samples, packet)
		if err != nil {
			c.Log.Warnf("opus encode failed: %v", err)
			continue
		}
		c.Log.Debugf("opus encoded %d bytes", n)
		audio := values.Audio{
			OpusPCM:   packet[:n],
			Timestamp: time.Now(),
		}
		raw, err := json.Marshal(audio)
		if err != nil {
			c.Log.Warnf("json marshal failed: %v", err)
			continue
		}
		fec, err := codec.FECEncoder.EncodeData(raw)
		if err != nil {
			c.Log.Warnf("fec encode failed: %v", err)
			continue
		}
		enc, err := encrypt.EncryptAES(fec, c.AESKey)
		if err != nil {
			c.Log.Warnf("aes encrypt failed: %v", err)
			continue
		}
		nWritten, err := c.Conn.Write(enc)
		if err != nil {
			c.Log.Warnf("network send failed: %v — stopping capture", err)
			return
		}
		c.Log.Tracef("sent %d bytes to server", nWritten)
	}
}

func (c *Client) InitCaptureDevice() *malgo.Device {
	denoiser, err := audio.NewDenoiseState()
	if err != nil {
		c.Log.Fatalf("failed to create denoiser: %v", err)
	}

	cfg := malgo.DefaultDeviceConfig(malgo.Capture)

	cfg.Capture.Format = malgo.FormatS16
	cfg.Capture.Channels = uint32(values.ClientchannelCount)
	cfg.SampleRate = uint32(values.ClientRate)
	cfg.PeriodSizeInFrames = audio.FrameSize
	onRecv := func(_, in []byte, framecount uint32) {

		c.Log.Debugf("received %d bytes from microphone", len(in))
		samples := BytesToInt16(in)

		// Denoise the audio
		denoisedSamples := denoiser.ProcessFrame(samples)

		select {
		case c.captureChan <- denoisedSamples:
		default:
			c.Log.Warn("capture channel full, dropping audio")
		}
	}
	deviceCallbacks := malgo.DeviceCallbacks{
		Data: onRecv,
	}
	device, err := malgo.InitDevice(c.AudioCtx.Context, cfg, deviceCallbacks)
	if err != nil {
		c.Log.Fatalf("capture device init failed: %v", err)
	}

	return device
}

func Int16SliceToBytes(data []int16) []byte {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data)*2)
}

func BytesToInt16(b []byte) []int16 {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Slice((*int16)(unsafe.Pointer(&b[0])), len(b)/2)
}
