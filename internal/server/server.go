package server

import (
	"context"
	"fmt"
	"sync"

	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/internal/utils/logger"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

type client struct {
	ClientID uuid.UUID
	Network  *sctp.SCTPConn
	AESkey   []byte
}

type Server struct {
	Rooms []*values.Room

	roomMu   sync.Mutex
	roomCond *sync.Cond

	Log *logger.Logger

	PrivateKey *ecies.PrivateKey
	Clients    map[uuid.UUID]*client
}

func New(log *logger.Logger) (*Server, error) {
	key, err := ecies.GenerateKey()
	if err != nil {
		return nil, err
	}
	s := &Server{
		Rooms:      []*values.Room{},
		Clients:    make(map[uuid.UUID]*client),
		Log:        log,
		PrivateKey: key,
	}
	s.roomCond = sync.NewCond(&s.roomMu)
	return s, nil
}

func (s *Server) Run(ctx context.Context, host, port string) error {
	addr, err := sctp.ResolveSCTPAddr(
		"sctp",
		fmt.Sprintf("%s:%s", host, port),
	)
	if err != nil {
		return err
	}
	listener, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	s.Log.Infof("server listening on %s:%s", host, port)

	go s.handleWriteToClients(ctx)

	go func() {
		<-ctx.Done()
		s.Log.Info("closing listener")
		listener.Close()
	}()

	for {
		conn, err := listener.AcceptSCTP()
		if err != nil {
			select {
			case <-ctx.Done():
				s.Log.Info("server shutdown complete")
				return nil
			default:
			}
			s.Log.WithField("error", err).Error("accept failed")
			continue
		}
		s.Log.WithField("remote", conn.RemoteAddr().String()).Debug("new connection accepted")
		go s.handleClient(conn)
	}
}
