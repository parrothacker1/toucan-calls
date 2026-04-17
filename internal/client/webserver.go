package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os/exec"
	"runtime"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// WSMessage represents a message exchanged over WebSocket
type WSMessage struct {
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	Username string          `json:"username,omitempty"`
	Password string          `json:"password,omitempty"`
	RoomID   string          `json:"roomId,omitempty"`
	Model    string          `json:"model,omitempty"`
	Message  string          `json:"message,omitempty"`
}

// WSEvent represents an event sent from Go backend to the frontend
type WSEvent struct {
	Type     string   `json:"type"`
	State    string   `json:"state,omitempty"`
	RoomID   string   `json:"roomId,omitempty"`
	IsSpeech *bool    `json:"isSpeech,omitempty"`
	Speakers []string `json:"speakers,omitempty"`
	Model    string   `json:"model,omitempty"`
	Message  string   `json:"message,omitempty"`
}

type WebServer struct {
	client    *Client
	conn      *websocket.Conn
	connMu    sync.Mutex
	server    *http.Server
	eventCh   chan WSEvent
	cancelBC  context.CancelFunc
	uiFS      fs.FS
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func newWebServer(c *Client, uiFS fs.FS) *WebServer {
	return &WebServer{
		client:  c,
		eventCh: make(chan WSEvent, 256),
		uiFS:    uiFS,
	}
}

func (ws *WebServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", ws.handleWebSocket)

	// Serve the embedded React SPA
	fileServer := http.FileServer(http.FS(ws.uiFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Strip leading slash; root maps to index.html
		if path == "/" || path == "" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Try to serve the file directly
		f, err := ws.uiFS.Open(path[1:])
		if err != nil {
			// SPA fallback: serve index.html for any unmatched route
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		f.Close()
		fileServer.ServeHTTP(w, r)
	})

	ws.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ws.client.Log.WithField("addr", addr).Info("starting web UI server")
	go func() {
		if err := ws.server.ListenAndServe(); err != http.ErrServerClosed {
			ws.client.Log.Fatalf("web server error: %v", err)
		}
	}()

	return nil
}

func (ws *WebServer) Stop() {
	if ws.server != nil {
		ws.server.Shutdown(context.Background())
	}
}

func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		ws.client.Log.Warnf("websocket upgrade failed: %v", err)
		return
	}

	// Cancel any previous broadcaster goroutine
	ws.connMu.Lock()
	if ws.cancelBC != nil {
		ws.cancelBC()
	}
	ws.conn = conn
	bcCtx, bcCancel := context.WithCancel(context.Background())
	ws.cancelBC = bcCancel
	ws.connMu.Unlock()

	ws.client.Log.Info("browser connected via WebSocket")

	// Send initial status
	ws.sendEvent(WSEvent{Type: "STATUS", State: "disconnected", Model: ws.client.Model})

	// Start event broadcaster for this connection
	go ws.broadcastEvents(bcCtx)

	// Read messages from browser
	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			ws.client.Log.Warnf("websocket read error: %v", err)
			break
		}
		ws.handleMessage(msg)
	}

	ws.connMu.Lock()
	ws.conn = nil
	bcCancel()
	ws.connMu.Unlock()
}

func (ws *WebServer) handleMessage(msg WSMessage) {
	defer func() {
		if r := recover(); r != nil {
			ws.client.Log.Errorf("panic in handleMessage(%s): %v", msg.Type, r)
			ws.sendEvent(WSEvent{Type: "ERROR", Message: fmt.Sprintf("internal error: %v", r)})
		}
	}()

	switch msg.Type {
	case "CONNECT":
		ws.sendEvent(WSEvent{Type: "STATUS", State: "connecting"})
		if err := ws.client.connect(); err != nil {
			ws.sendEvent(WSEvent{Type: "ERROR", Message: fmt.Sprintf("connection failed: %v", err)})
			ws.sendEvent(WSEvent{Type: "STATUS", State: "disconnected"})
			return
		}
		ws.sendEvent(WSEvent{Type: "STATUS", State: "handshaking"})
		if err := ws.client.handshake(); err != nil {
			ws.sendEvent(WSEvent{Type: "ERROR", Message: fmt.Sprintf("handshake failed: %v", err)})
			ws.sendEvent(WSEvent{Type: "STATUS", State: "disconnected"})
			return
		}
		ws.sendEvent(WSEvent{Type: "STATUS", State: "connected"})

	case "AUTH":
		ws.sendEvent(WSEvent{Type: "STATUS", State: "authenticating"})
		if err := ws.client.authenticate(msg.Username, msg.Password); err != nil {
			ws.sendEvent(WSEvent{Type: "ERROR", Message: "authentication failed"})
			ws.sendEvent(WSEvent{Type: "STATUS", State: "connected"})
			return
		}
		ws.sendEvent(WSEvent{Type: "STATUS", State: "authenticated"})

	case "CREATE_ROOM":
		roomID := uuid.New().String()
		if err := ws.client.joinRoomByID(roomID); err != nil {
			ws.sendEvent(WSEvent{Type: "ERROR", Message: fmt.Sprintf("create room failed: %v", err)})
			return
		}
		ws.sendEvent(WSEvent{Type: "ROOM_JOINED", RoomID: roomID})
		ws.sendEvent(WSEvent{Type: "STATUS", State: "in_room"})
		ws.startAudio()

	case "JOIN_ROOM":
		if msg.RoomID == "" {
			ws.sendEvent(WSEvent{Type: "ERROR", Message: "room ID required"})
			return
		}
		if err := ws.client.joinRoomByID(msg.RoomID); err != nil {
			ws.sendEvent(WSEvent{Type: "ERROR", Message: fmt.Sprintf("join room failed: %v", err)})
			return
		}
		ws.sendEvent(WSEvent{Type: "ROOM_JOINED", RoomID: msg.RoomID})
		ws.sendEvent(WSEvent{Type: "STATUS", State: "in_room"})
		ws.startAudio()

	case "SWITCH_MODEL":
		if msg.Model == "vad" || msg.Model == "ml" {
			ws.client.Model = msg.Model
			ws.sendEvent(WSEvent{Type: "MODEL_CHANGED", Model: msg.Model})
			ws.client.Log.WithField("model", msg.Model).Info("model switched via UI")
		}

	case "SHUTDOWN":
		ws.client.Shutdown()
	}
}

func (ws *WebServer) startAudio() {
	playback := ws.client.InitPlaybackDevice()
	capture := ws.client.InitCaptureDevice()
	playback.Start()
	if err := capture.Start(); err != nil {
		ws.client.Log.Fatalf("capture start failed: %v", err)
	}
	ws.client.Log.Info("audio devices started via UI")
	go ws.client.readLoop()
	go ws.client.ProcessCapture()
}

func (ws *WebServer) sendEvent(event WSEvent) {
	select {
	case ws.eventCh <- event:
	default:
		// Drop if channel full
	}
}

func (ws *WebServer) broadcastEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ws.eventCh:
			ws.connMu.Lock()
			conn := ws.conn
			ws.connMu.Unlock()

			if conn == nil {
				continue
			}
			if err := conn.WriteJSON(event); err != nil {
				ws.client.Log.Warnf("websocket write error: %v", err)
			}
		}
	}
}

// SendUIEvent allows other parts of the client to send events to the UI
func (c *Client) SendUIEvent(event WSEvent) {
	if c.webServer != nil {
		c.webServer.sendEvent(event)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		cmd.Start()
	}
}
