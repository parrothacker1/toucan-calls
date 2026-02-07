package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"bytes"

	ecies "github.com/ecies/go/v2"
	"github.com/gen2brain/malgo"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	"github.com/sirupsen/logrus"

	_ "github.com/toucan/toucan-calls/utils"
	"github.com/toucan/toucan-calls/utils/encrypt"
	"github.com/toucan/toucan-calls/utils/values"
)

var audioCtx *malgo.AllocatedContext

func init() {
	switch os.Getenv("LOG_LEVEL") {
	case "DEBUG":
		logrus.SetLevel(logrus.DebugLevel)
	case "INFO":
		logrus.SetLevel(logrus.InfoLevel)
	case "ERROR":
		logrus.SetLevel(logrus.ErrorLevel)
	case "WARN":
		logrus.SetLevel(logrus.WarnLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}

func main() {
	host := os.Getenv("HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// AES Key
	values.AESKey = make([]byte, 32)
	if _, err := rand.Read(values.AESKey); err != nil {
		logrus.Fatalf("AES key error: %v", err)
	}

	// Init audio context
	ctx, err := malgo.InitContext(nil, malgo.ContextConfig{}, nil)
	if err != nil {
		logrus.Fatalf("Audio init failed: %v", err)
	}
	audioCtx = ctx
	defer audioCtx.Uninit()

	// Resolve server
	addr, err := sctp.ResolveSCTPAddr("sctp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		logrus.Fatalf("Resolve error: %v", err)
	}

	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		logrus.Fatalf("Connection error: %v", err)
	}
	logrus.Infof("Connected to %s", conn.RemoteAddr())

	// Graceful exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		conn.Write([]byte("EXT"))
		time.Sleep(200 * time.Millisecond)
		conn.Close()
		os.Exit(0)
	}()

	// ECC handshake
	pubKeyBuf := make([]byte, 128)
	n, _ := conn.Read(pubKeyBuf)
	values.PublicKey, _ = ecies.NewPublicKeyFromHex(string(pubKeyBuf[:n]))
	encAES, _ := ecies.Encrypt(values.PublicKey, values.AESKey)
	conn.Write(encAES)
	ack := make([]byte, 64)
	conn.Read(ack)

	// Room logic
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("1.Create a room\n2.Join a room\nOption -> ")
	choice, _ := reader.ReadString('\n')
	choice = choice[:len(choice)-1]

	var roomID string
	if choice == "1" {
		roomID = uuid.New().String()
		logrus.Infof("Room ID: %s", roomID)
	} else {
		fmt.Print("Enter Room ID: ")
		roomID, _ = reader.ReadString('\n')
		roomID = roomID[:len(roomID)-1]
	}

	roomEnc, _ := encrypt.EncryptAES([]byte(roomID), values.AESKey)
	conn.Write(roomEnc)

	var wg sync.WaitGroup
	wg.Add(3)

	go ClientRead(conn)
	go ClientWrite(audioCtx, conn)
	go ClientPlayback(audioCtx)

	wg.Wait()
}

// ================= AUDIO PLAYBACK =================

func ClientPlayback(ctx *malgo.AllocatedContext) {
	cfg := malgo.DefaultDeviceConfig(malgo.Playback)
	cfg.Playback.Format = malgo.FormatS16
	cfg.Playback.Channels = uint32(values.ClientchannelCount)
	cfg.SampleRate = uint32(values.ClientRate)

	cfg.DataCallback = malgo.DataProc(func(out, _ []byte, _ uint32) {
		select {
		case chunk := <-values.ClientAudioBuffer:
			copy(out, int16ToBytes(chunk))
		default:
			for i := range out {
				out[i] = 0
			}
		}
	})

	device, err := malgo.InitDevice(ctx.Context, cfg, nil)
	if err != nil {
		logrus.Fatalf("Playback init error: %v", err)
	}
	defer device.Uninit()
	device.Start()
	select {}
}

// ================= AUDIO CAPTURE =================

func ClientWrite(ctx *malgo.AllocatedContext, conn *sctp.SCTPConn) {
	cfg := malgo.DefaultDeviceConfig(malgo.Capture)
	cfg.Capture.Format = malgo.FormatS16
	cfg.Capture.Channels = uint32(values.ClientchannelCount)
	cfg.SampleRate = uint32(values.ClientRate)

	cfg.DataCallback = malgo.DataProc(func(_, in []byte, _ uint32) {
		samples := bytesToInt16(in)
		packet := make([]byte, 1024)

		n, err := values.OpusEncoder.Encode(samples, packet)
		if err != nil {
			return
		}

		audio := values.Audio{
			OpusPCM:   packet[:n],
			Timestamp: time.Now(),
		}

		raw, _ := json.Marshal(audio)
		fec, _ := values.FECEncoder.EncodeData(raw)
		enc, _ := encrypt.EncryptAES(fec, values.AESKey)
		conn.Write(enc)
	})

	device, err := malgo.InitDevice(ctx.Context, cfg, nil)
	if err != nil {
		logrus.Fatalf("Capture init error: %v", err)
	}
	defer device.Uninit()
	device.Start()
	select {}
}

// ================= NETWORK READ =================

func ClientRead(conn *sctp.SCTPConn) {
	for {
		buf := make([]byte, 1024*100)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		dec, _ := encrypt.DecryptAES(buf[:n], values.AESKey)
		data, _, _ := values.FECEncoder.DecodeData(dec)

		count := values.ClientchannelCount * values.ClientframesPerBuffer * values.ClientRate / 1000
		audio := make([]int16, count)
		values.OpusDecoder.Decode(data, audio)

		select {
		case values.ClientAudioBuffer <- audio:
		default:
		}
	}
}

// ================= HELPERS =================

func int16ToBytes(data []int16) []byte {
	buf := new(bytes.Buffer)
	for _, v := range data {
		buf.WriteByte(byte(v))
		buf.WriteByte(byte(v >> 8))
	}
	return buf.Bytes()
}

func bytesToInt16(data []byte) []int16 {
	samples := make([]int16, len(data)/2)
	for i := range samples {
		samples[i] = int16(data[i*2]) | int16(data[i*2+1])<<8
	}
	return samples
}
