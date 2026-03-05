package client

import (
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/gen2brain/malgo"
	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/internal/utils/logger"
)

type Client struct {
	Host string
	Port string

	Conn     *sctp.SCTPConn
	AudioCtx *malgo.AllocatedContext

	captureChan chan []int16
	playbackBuf chan []int16

	AESKey    []byte
	PublicKey *ecies.PublicKey

	Log *logger.Logger
}

func New(host, port string, log *logger.Logger) *Client {
	return &Client{
		Host:        host,
		Port:        port,
		Log:         log,
		captureChan: make(chan []int16, 128),
		playbackBuf: make(chan []int16, 30),
	}
}

func (c *Client) Run() error {
	if err := c.initAudioContext(); err != nil {
		return err
	}
	if err := c.connect(); err != nil {
		return err
	}
	if err := c.handshake(); err != nil {
		return err
	}
	if err := c.joinRoom(); err != nil {
		return err
	}
	playback := c.initPlaybackDevice()
	capture := c.initCaptureDevice()

	playback.Start()
	if err := capture.Start(); err != nil {
		c.Log.Fatalf("capture start failed: %v", err)
	}
	c.Log.Info("capture device started")

	go c.readLoop()

	select {}
}

func (c *Client) Shutdown() {
	if c.Conn != nil {
		c.Log.Info("sending exit signal to server")
		c.Conn.Write([]byte("EXT"))
		time.Sleep(200 * time.Millisecond)
		c.Conn.Close()
	}
	if c.AudioCtx != nil {
		c.AudioCtx.Uninit()
		c.AudioCtx.Free()
	}
}
