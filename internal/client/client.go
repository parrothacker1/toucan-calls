package client

import (
	"fmt"
	"io/fs"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/gen2brain/malgo"
	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/internal/utils/logger"
)

type Client struct {
	Host   string
	Port   string
	Model  string
	VadURL string

	Conn     *sctp.SCTPConn
	AudioCtx *malgo.AllocatedContext

	captureChan chan []int16
	playbackBuf chan []int16
	done        chan struct{} // signals connection closed

	AESKey    []byte
	PublicKey *ecies.PublicKey

	Log       *logger.Logger
	webServer *WebServer
}

func New(host, port, model, vadURL string, log *logger.Logger) *Client {
	return &Client{
		Host:        host,
		Port:        port,
		Model:       model,
		VadURL:      vadURL,
		Log:         log,
		captureChan: make(chan []int16, 128),
		playbackBuf: make(chan []int16, 30),
		done:        make(chan struct{}),
	}
}

func (c *Client) Run() error {
	if err := c.InitAudioContext(); err != nil {
		return err
	}
	if err := c.connect(); err != nil {
		return err
	}
	if err := c.handshake(); err != nil {
		return err
	}

	username, password := promptCredentials()
	if err := c.authenticate(username, password); err != nil {
		return err
	}
	if err := c.joinRoom(); err != nil {
		return err
	}
	playback := c.InitPlaybackDevice()
	capture := c.InitCaptureDevice()
	playback.Start()
	if err := capture.Start(); err != nil {
		c.Log.Fatalf("capture start failed: %v", err)
	}

	c.Log.Info("capture device started")

	go c.readLoop()
	go c.ProcessCapture()
	select {}
}

// RunWithUI starts the client in web UI mode.
// Instead of prompting via stdin, the React SPA drives the lifecycle via WebSocket.
func (c *Client) RunWithUI(uiFS fs.FS, webPort string) error {
	if err := c.InitAudioContext(); err != nil {
		return err
	}

	ws := newWebServer(c, uiFS)
	c.webServer = ws

	addr := ":" + webPort
	if err := ws.Start(addr); err != nil {
		return fmt.Errorf("web server start failed: %w", err)
	}

	url := fmt.Sprintf("http://localhost:%s", webPort)
	c.Log.Infof("web UI available at %s", url)
	openBrowser(url)

	// Block forever — lifecycle is driven by WebSocket commands
	select {}
}

func (c *Client) Shutdown() {
	// Signal audio loops to stop
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	if c.webServer != nil {
		c.webServer.Stop()
	}
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
