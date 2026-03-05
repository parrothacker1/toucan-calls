package server

import (
	"context"
	"sync"
	"time"

	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (s *Server) handleWriteToClients(ctx context.Context) {
	var activeRooms sync.Map
	s.roomMu.Lock()
	if len(s.Rooms) == 0 {
		s.Log.Debug("waiting for clients...")
		s.roomCond.Wait()
	}
	s.roomMu.Unlock()
	for {
		s.roomMu.Lock()
		select {
		case <-ctx.Done():
			s.Log.Debug("writer shutdown")
			s.roomMu.Unlock()
			return
		default:
			if len(s.Rooms) == 0 {
				s.Log.Debug("waiting for new client")
				s.roomCond.Wait()
			} else {
				for _, room := range s.Rooms {
					if _, exists := activeRooms.Load(room.RoomID); !exists {
						activeRooms.Store(room.RoomID, struct{}{})
						go func(room *values.Room) {
							defer activeRooms.Delete(room.RoomID)
							for {
								room.Mu.Lock()
								if len(room.Clients) == 0 {
									s.Log.WithField("room_id", room.RoomID.String()).Debug("room empty stopping writer")
									room.Mu.Unlock()
									return
								}
								time.Sleep(1 * time.Second)
								room.Mu.Unlock()
							}
						}(room)
					}
				}
			}
		}
		s.roomMu.Unlock()
	}
}
