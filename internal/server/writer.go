package server

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/toucan/toucan-calls/internal/utils/codec"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (s *Server) handleWriteToClients(ctx context.Context) {
	var activeRooms sync.Map
	for {
		select {
		case <-ctx.Done():
			s.Log.Debug("writer shutdown")
			return
		default:
			s.roomMu.Lock()
			if len(s.Rooms) == 0 {
				s.roomCond.Wait()
				s.roomMu.Unlock()
				continue
			}
			for _, room := range s.Rooms {
				if _, exists := activeRooms.Load(room.RoomID); exists {
					continue
				}
				activeRooms.Store(room.RoomID, struct{}{})
				go func(room *values.Room) {
					defer activeRooms.Delete(room.RoomID)
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}
						room.Mu.Lock()
						room.AudioBuf.Mu.Lock()
						if len(room.Clients) == 0 {
							room.AudioBuf.Mu.Unlock()
							room.Mu.Unlock()
							s.Log.WithField("room_id", room.RoomID.String()).Debug("room empty stopping writer")
							return
						}
						clients := make([]uuid.UUID, len(room.Clients))
						copy(clients, room.Clients)
						if len(room.AudioBuf.Buffer) == 0 {
							room.AudioBuf.Mu.Unlock()
							room.Mu.Unlock()
							time.Sleep(20 * time.Millisecond)
							continue
						}
						chunks := room.AudioBuf.Buffer
						room.AudioBuf.Buffer = nil
						room.AudioBuf.Mu.Unlock()
						room.Mu.Unlock()

						s.Log.WithField("room_id", room.RoomID.String()).Tracef("writer processing %d chunks", len(chunks))
						s.Log.WithField("room_id", room.RoomID.String()).Tracef("room has %d clients", len(clients))

						packet := make([]byte, 1024)
						for _, chunk := range chunks {
							for _, id := range clients {
								s.clientsMu.RLock()
								client := s.Clients[id]
								s.clientsMu.RUnlock()
								if client == nil {
									s.Log.WithField("client_id", id.String()).Warn("client lookup returned nil")
									continue
								}
								n, err := codec.OpusEncoder.Encode(chunk.BasePCM, packet)
								if err != nil {
									continue
								}
								audio := values.Audio{OpusPCM: packet[:n], Timestamp: chunk.Timestamp}
								raw, _ := json.Marshal(audio)
								fec, _ := codec.FECEncoder.EncodeData(raw)
								enc, _ := encrypt.EncryptAES(fec, client.AESkey)

								nwrite, err := client.Network.Write(enc)
								if err != nil {
									s.Log.WithField("client_id", id.String()).Warnf("send failed: %v", err)
									continue
								}
								s.Log.WithField("client_id", id.String()).Tracef("sent %d bytes to client", nwrite)
							}
						}
					}
				}(room)
			}
			s.roomMu.Unlock()
		}
	}
}
