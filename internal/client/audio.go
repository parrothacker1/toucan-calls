package client

import (
	"encoding/json"
	"time"
	"unsafe"

	"github.com/gen2brain/malgo"
	"github.com/toucan/toucan-calls/internal/utils/codec"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (c *Client) initAudioContext() error {
	ctx, err := malgo.InitContext(nil, malgo.ContextConfig{}, nil)
	if err != nil {
		return err
	}
	c.AudioCtx = ctx
	return nil
}

func (c *Client) initPlaybackDevice() *malgo.Device {
	cfg := malgo.DefaultDeviceConfig(malgo.Playback)
	cfg.Playback.Format = malgo.FormatS16
	cfg.Playback.Channels = uint32(values.ClientchannelCount)
	cfg.SampleRate = uint32(values.ClientRate)
	cfg.Alsa.NoMMap = 1
	onSamples := func(out, _ []byte, framecount uint32) {
		select {
		case chunk := <-c.playbackBuf:
			copy(out, int16SliceToBytes(chunk))
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

func (c *Client) processCapture() {
	c.Log.Info("capture processing loop started")
	packet := make([]byte, 1024)
	for samples := range c.captureChan {
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
			c.Log.Warnf("network send failed: %v", err)
			continue
		}
		c.Log.Tracef("sent %d bytes to server", nWritten)
	}
}

func (c *Client) initCaptureDevice() *malgo.Device {
	cfg := malgo.DefaultDeviceConfig(malgo.Capture)

	cfg.Capture.Format = malgo.FormatS16
	cfg.Capture.Channels = uint32(values.ClientchannelCount)
	cfg.SampleRate = uint32(values.ClientRate)
	cfg.PeriodSizeInFrames = 960
	onRecv := func(_, in []byte, framecount uint32) {

		c.Log.Debugf("received %d bytes from microphone", len(in))
		samples := bytesToInt16(in)
		select {
		case c.captureChan <- samples:
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

	go c.processCapture()
	return device
}

func int16SliceToBytes(data []int16) []byte {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data)*2)
}

func bytesToInt16(b []byte) []int16 {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Slice((*int16)(unsafe.Pointer(&b[0])), len(b)/2)
}
