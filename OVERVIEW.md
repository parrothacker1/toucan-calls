# Toucan-Calls — Encrypted VoIP System

## What is it?

Toucan-Calls is a **real-time encrypted voice chat system** built from scratch in Go. Think Discord voice channels, but with custom encryption, custom audio processing, and ML-powered speaker detection — all handwritten, no frameworks.

Two or more people run the client on their machines, connect to a central server, join a "room", and talk. Everything is encrypted end-to-end with keys that are negotiated fresh for every session.

---

## How the connection works

When a client starts, this is what happens step by step:

```
Client                                    Server
  |                                         |
  |──── SCTP Connect (port 3000) ──────────>|
  |                                         |
  |<──── Server's Public Key (hex) ─────────|
  |   Client checks SHA-256 hash against    |
  |   a pinned hash (prevents MITM attacks) |
  |                                         |
  |──── Encrypted AES-256 Key (ECIES) ─────>|
  |   Client generates a random 32-byte     |
  |   session key, encrypts it with the     |
  |   server's public key. Only the server  |
  |   can decrypt it.                       |
  |                                         |
  |<──── ACK ───────────────────────────────|
  |                                         |
  |──── Username + Password (AES encrypted)>|
  |                                         |
  |<──── AUTH_OK ───────────────────────────|
  |                                         |
  |──── Room UUID (AES encrypted) ─────────>|
  |                                         |
  |<════ Bidirectional Encrypted Audio ════>|
```

**SCTP** (Stream Control Transmission Protocol) is used instead of TCP or UDP. It's the protocol used in 4G/5G telecom signaling. It gives message-oriented delivery (like UDP) with reliability features (like TCP), and avoids head-of-line blocking which is critical for voice — if one packet is delayed, it doesn't block everything behind it.

---

## The encryption

There are two layers:

### 1. ECIES (Elliptic Curve Integrated Encryption Scheme)

Used only during the handshake. The server has a permanent elliptic curve private key. The client receives the server's public key, verifies its SHA-256 fingerprint against a **pinned hash** compiled into the binary (this is how the client knows it's talking to the real server, not an attacker — same concept as certificate pinning in mobile apps). Then the client generates a random AES key, encrypts it with the server's public key using ECIES, and sends it. Only the server can decrypt it because only the server has the private key.

### 2. AES-256-GCM

Used for everything after the handshake. GCM (Galois/Counter Mode) is an AEAD cipher — it provides both **confidentiality** (nobody can read the data) and **integrity** (nobody can tamper with it without detection). Every packet gets a fresh random 96-bit nonce prepended to the ciphertext.

Authentication uses **bcrypt** password hashing stored in SQLite. Passwords are never sent in plain text — they're encrypted with the session AES key before transmission.

---

## The audio pipeline

This is where it gets interesting. Every audio frame goes through 5 stages before hitting the network:

```
Microphone (48kHz, 16-bit, mono)
    |
[1] RNNoise — Neural network noise suppression
    |
[2] Opus Encoder — Audio compression
    |
[3] Reed-Solomon FEC — Error correction codes
    |
[4] AES-256-GCM — Encryption
    |
[5] SCTP Send -> Server
```

**[1] RNNoise** — A C library from Mozilla Research. It's a recurrent neural network trained to remove background noise in real-time: keyboard clicks, fan noise, room echo, etc. It processes 480 samples at a time (~10ms at 48kHz). Bound to Go via CGO (Go calling C code directly).

**[2] Opus** — The industry-standard audio codec. Used by Discord, Zoom, WebRTC, and basically every modern voice app. It compresses raw PCM audio from ~1.5 Mbps down to ~32-64 kbps while preserving voice clarity. The encoder is tuned for "VoIP" application mode — optimized for speech, low latency (~20ms frames).

**[3] Reed-Solomon Forward Error Correction** — This is the clever part. The audio data is split into 6 data shards and 3 parity shards (9 total). If up to 3 shards are lost or corrupted during transmission, the original data can be **fully reconstructed** without asking for a retransmission. This is critical for real-time audio — you can't pause a conversation to wait for a retransmit. The same math is used in QR codes, CDs, and satellite communications.

**[4] AES-256-GCM encryption** — As described above. Every packet encrypted with a fresh nonce.

**[5] SCTP transmission** — The encrypted blob is sent to the server.

The server receives packets from all clients in a room, decrypts them, decodes FEC, and re-broadcasts to all other clients. Each recipient's client then runs the pipeline in reverse: decrypt -> FEC decode -> Opus decode -> speaker output.

---

## The ML/AI layer

On top of the voice pipeline, there's a Python ML service running two models:

### VAD (Voice Activity Detection)

**What it does**: Answers "Is someone speaking right now, or is it silence?"

Uses **WebRTC VAD** — Google's voice activity detector from the WebRTC project (the same technology behind Google Meet). It's set to aggressiveness level 3 (most aggressive — fewer false positives, might miss very quiet speech). Takes a small audio frame, returns `true` or `false`.

**Why it matters**: The UI shows a real-time pulsing green dot when speech is detected. You could also use it to stop transmitting during silence (saves bandwidth).

### Speaker Diarization (the "ML" model)

**What it does**: Answers the harder question — "**Who** is speaking, and **when**?"

This uses two neural networks running via **Sherpa-ONNX** (an inference framework from the Next-gen Kaldi project, which is the leading open-source speech recognition toolkit):

1. **Pyannote Segmentation 3.0** — From the pyannote.audio project (by Herve Bredin at CNRS, France). This neural network segments audio into regions of "who spoke when". It's trained on thousands of hours of conversational speech data. It outputs temporal boundaries: "someone is speaking from 0.5s to 2.3s, someone else from 2.5s to 4.1s".

2. **3D-Speaker ERes2Net** — From Alibaba's 3D-Speaker project. This is a speaker **embedding** model trained on the VoxCeleb dataset (celebrity speech recordings). It converts a chunk of audio into a fixed-size numerical vector (an "embedding") that uniquely represents that person's voice. Two audio chunks from the same person will produce similar vectors; different people will produce different vectors. Think of it like a "voiceprint" — analogous to a fingerprint but for voice.

**How they work together**: The segmentation model finds speech boundaries in the audio. The embedding model extracts a voiceprint for each segment. Then a clustering algorithm groups segments by speaker identity (segments with similar voiceprints = same person). The final output looks like:
```json
[
  {"speaker": "speaker_0", "start": 0.5, "end": 2.3},
  {"speaker": "speaker_1", "start": 2.5, "end": 4.1}
]
```

The Python service keeps a **10-second rolling buffer** of audio and runs offline diarization on it every time new audio arrives — this is a way to approximate real-time diarization without the complexity of a full streaming pipeline.

Both models run as ONNX (Open Neural Network Exchange) models, which means they were trained in PyTorch but exported to a portable format that runs efficiently via the ONNX Runtime (Microsoft's high-performance inference engine).

---

## The Web UI

The client has a **React + TypeScript** web frontend (built with Vite) embedded directly into the Go binary using `go:embed`. When you run the client with `--ui`, it starts an HTTP server on port 8080, auto-opens your browser, and you get:

- **Auth screen** — Username/password login
- **Room screen** — Create or join a room (UUID-based), see active speakers, real-time VAD speech indicator (pulsing green dot)
- **Settings panel** — Toggle between VAD and ML diarization models
- **Live status** — Connection state indicator (disconnected -> connecting -> handshaking -> authenticated -> in room)

The browser communicates with the Go client via **WebSocket** — real-time bidirectional JSON messages. The Go client drives the SCTP connection to the server while the browser provides the interface.

Dark theme with an "Anvil" aesthetic — `#0a0a0f` backgrounds, orange/teal accent colors.

---

## The telemetry stack

**Grafana + Loki** for log aggregation and visualization:

- **Loki** (by Grafana Labs) — A log aggregation system. Like Prometheus but for logs. The Go server pushes structured log batches to Loki's HTTP push API with labels like `{job="toucan-calls", service="server", level="info"}`. It stores logs efficiently and makes them queryable.

- **Grafana** — Visualization dashboard. Pre-configured with Loki as a data source. You can query logs in real-time at `http://localhost:3001` using LogQL queries like `{job="toucan-calls"} |= "handshake"`.

Both run as Docker containers alongside the server.

---

## The custom event queue

The logging system doesn't use any off-the-shelf library. It's built on a **lock-free MPSC (Multi-Producer, Single-Consumer) ring buffer** based on the **Dmitry Vyukov queue model** — a well-known concurrent data structure from the systems programming world.

Multiple goroutines (threads) push log events simultaneously using atomic CAS (Compare-And-Swap) operations instead of mutexes — this means minimal lock contention even under heavy load. The queue is a linked list of ring buffer nodes, each with 64 slots and 64-byte padding between head/tail pointers to prevent **false sharing** (a CPU cache-line optimization). A single consumer goroutine drains events every 5ms and batches them to the writers (stdout + Loki).

---

## How it all runs

```bash
# Start the infrastructure (server, VAD service, Loki, Grafana)
docker compose up --build

# Run a client (CLI mode)
go run cmd/client/client.go

# Run a client (Web UI mode)
go run cmd/client/client.go --ui
# Browser opens at http://localhost:8080

# Grafana dashboard
# http://localhost:3001 -> Explore -> {job="toucan-calls"}
```

---

## Tech stack summary

| Layer | Technology |
|-------|-----------|
| Language | Go 1.25, Python 3.13 |
| Transport | SCTP (telecom-grade protocol) |
| Key Exchange | ECIES (elliptic curve) with SHA-256 key pinning |
| Encryption | AES-256-GCM (authenticated encryption) |
| Audio Codec | Opus (same as Discord/Zoom) |
| Noise Suppression | RNNoise (Mozilla, C library via CGO) |
| Error Correction | Reed-Solomon FEC (6 data + 3 parity shards) |
| Voice Detection | WebRTC VAD (Google) |
| Speaker ID | Pyannote 3.0 + 3D-Speaker ERes2Net (ONNX) |
| Auth | bcrypt + SQLite |
| Frontend | React + TypeScript + Vite, go:embed |
| Telemetry | Grafana + Loki |
| Logging | Custom lock-free MPSC queue (Vyukov model) |
| Containers | Docker Compose |

---

## Project structure

```
toucan-calls/
|-- cmd/
|   |-- client/client.go          # CLI client entry point
|   |-- server/server.go          # Server entry point
|-- internal/
|   |-- audio/rnnoise.go          # RNNoise C bindings (noise suppression)
|   |-- auth/                     # bcrypt + SQLite user auth
|   |-- client/                   # Client: SCTP, handshake, audio, web UI
|   |-- server/                   # Server: handler, writer, room management
|   |-- merkle/                   # Merkle tree (data integrity primitives)
|   |-- config/                   # Configuration structures
|   |-- utils/
|       |-- codec/                # Opus encoder/decoder, FEC
|       |-- encoder/              # Reed-Solomon forward error correction
|       |-- encrypt/              # AES-256-GCM encryption
|       |-- events/               # Lock-free MPSC event queue
|       |-- logger/               # Structured async logger + Loki writer
|       |-- values/               # Shared constants and data structures
|       |-- conversion/           # Audio buffer utilities
|-- python/                       # Flask ML service (VAD + diarization)
|-- ui/                           # React + TypeScript frontend (Vite)
|-- third_party/rnnoise/          # RNNoise C library
|-- infra/                        # Grafana + Loki provisioning configs
|-- docker-compose.yml
|-- Dockerfile
|-- Makefile
```
