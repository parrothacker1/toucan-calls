package server

import (
	"github.com/google/uuid"
	"github.com/toucan/toucan-calls/internal/utils/logger"
)

func (s *Server) removeClient(c *client, roomUUID uuid.UUID) {
	s.roomMu.Lock()
	defer s.roomMu.Unlock()
	roomIndex := -1
	for i, room := range s.Rooms {
		if roomUUID == room.RoomID {
			roomIndex = i
			break
		}
	}
	if roomIndex == -1 {
		s.Log.Error("room does not exist while removing client")
		return
	}
	room := s.Rooms[roomIndex]
	clientIndex := -1
	for i, id := range room.Clients {
		if c.ClientID == id {
			clientIndex = i
			break
		}
	}
	if clientIndex == -1 {
		s.Log.WithField("client_id", c.ClientID.String()).Error("client not found in room")
		return
	}
	room.Clients = append(
		room.Clients[:clientIndex],
		room.Clients[clientIndex+1:]...,
	)

	s.clientsMu.Lock()
	delete(s.Clients, c.ClientID)
	s.clientsMu.Unlock()
	if len(room.Clients) == 0 {
		s.Log.WithField("room_id", room.RoomID.String()).Debug("removing empty room")
		s.Rooms = append(
			s.Rooms[:roomIndex],
			s.Rooms[roomIndex+1:]...,
		)
	} else {
		s.Log.WithFields(logger.Fields{
			"room_id":   room.RoomID.String(),
			"client_id": c.ClientID.String(),
		}).Debug("removing client from room")
	}
}
