package server

import (
	"encoding/json"

	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/internal/utils/codec"
	"github.com/toucan/toucan-calls/internal/utils/conversion"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (s *Server) handleClient(con *sctp.SCTPConn) {
	remote := con.RemoteAddr().String()
	s.Log.WithField("remote", remote).
		Debug("sending server public key")
	_, err := con.Write([]byte(s.PrivateKey.PublicKey.Hex(true)))
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("failed sending public key: %v", err)
		return
	}
	aesEnc := make([]byte, 256)
	keySize, err := con.Read(aesEnc)
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("failed reading AES key: %v", err)
		return
	}
	aesKey, err := ecies.Decrypt(s.PrivateKey, aesEnc[:keySize])
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("AES decrypt failed: %v", err)
		return
	}
	s.Log.WithField("remote", remote).
		Debug("AES session key established")

	_, err = con.Write(values.ACKMessage)
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("failed sending ACK: %v", err)
		return
	}

	authBuf := make([]byte, 1024)
	authSize, err := con.Read(authBuf)
	if err != nil {
		s.Log.Errorf("auth read failed: %v", err)
		con.Close()
		return
	}
	authDec, err := encrypt.DecryptAES(authBuf[:authSize], aesKey)
	if err != nil {
		s.Log.Errorf("auth decrypt failed: %v", err)
		con.Close()
		return
	}
	var authMsg values.AuthMessage
	err = json.Unmarshal(authDec, &authMsg)
	if err != nil {
		s.Log.Errorf("auth json failed: %v", err)
		con.Close()
		return
	}
	_, err = s.Auth.Login(authMsg.Username, authMsg.Password)
	if err != nil {
		con.Write([]byte("AUTH_FAIL"))
		s.Log.WithField("user", authMsg.Username).Warn("auth failed")
		con.Close()
		return
	}
	con.Write([]byte("AUTH_OK"))
	s.Log.WithField("user", authMsg.Username).Info("auth success")
	_, err = con.Write(values.ACKMessage)
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("failed sending ACK: %v", err)
		return
	}
	roomBuf := make([]byte, 128)
	roomSize, err := con.Read(roomBuf)
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("failed reading room id: %v", err)
		return
	}

	roomID, err := encrypt.DecryptAES(roomBuf[:roomSize], aesKey)
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("room id decrypt failed: %v", err)
		return
	}
	roomUUID, err := uuid.Parse(string(roomID))
	if err != nil {
		s.Log.WithField("remote", remote).
			Errorf("invalid room uuid: %v", err)
		return
	}

	s.roomMu.Lock()
	existingRoomIndex := -1
	for i, room := range s.Rooms {
		if roomUUID == room.RoomID {
			existingRoomIndex = i
			break
		}
	}

	thisClient := client{
		Network:  con,
		AESkey:   aesKey,
		ClientID: uuid.New(),
	}

	var thisRoom *values.Room
	if existingRoomIndex > -1 {
		thisRoom = s.Rooms[existingRoomIndex]
		thisRoom.Clients =
			append(thisRoom.Clients, thisClient.ClientID)
		s.Log.WithField("room_id", roomUUID.String()).
			Debug("client joined room")
	} else {
		thisRoom = &values.Room{
			RoomID:  roomUUID,
			Clients: []uuid.UUID{},
			AudioBuf: &values.AudioBuffer{
				Buffer: []*values.AudioChunk{},
			},
		}
		thisRoom.Clients =
			append(thisRoom.Clients, thisClient.ClientID)
		s.Rooms = append(s.Rooms, thisRoom)
		s.roomCond.Signal()
		s.Log.WithField("room_id", roomUUID.String()).
			Info("created new room")
	}

	s.roomMu.Unlock()

	s.clientsMu.Lock()
	s.Clients[thisClient.ClientID] = &thisClient
	s.clientsMu.Unlock()

	clog := s.Log.WithField("client_id", thisClient.ClientID.String())
	for {
		msgBuf := make([]byte, 1024*100)
		msgSize, err := con.Read(msgBuf)
		if err != nil {
			clog.Errorf("read error: %v", err)
			s.removeClient(&thisClient, roomUUID)
			return
		}
		clog.Tracef("received %d bytes from client", msgSize)
		if msgSize <= 3 {
			if string(msgBuf[:msgSize]) == "EXT" {
				clog.Debug("client disconnected")
				s.removeClient(&thisClient, roomUUID)
				return
			}
			continue
		}
		msgEnc, err := encrypt.DecryptAES(msgBuf[:msgSize], thisClient.AESkey)
		if err != nil {
			clog.Warnf("AES decrypt failed: %v", err)
			continue
		}
		clog.Tracef("after AES decrypt: %d bytes", len(msgEnc))
		msgDec, _, err := codec.FECEncoder.DecodeData(msgEnc)
		if err != nil {
			clog.Warnf("FEC decode failed: %v", err)
			continue
		}
		clog.Tracef("after FEC decode: %d bytes", len(msgDec))
		var audioMsg values.Audio
		err = json.Unmarshal(msgDec, &audioMsg)
		if err != nil {
			clog.Warnf("json unmarshal failed: %v", err)
			continue
		}
		clog.Trace("audio packet parsed")
		const frameSize = 960
		msgPCM := make([]int16, frameSize)
		_, err = codec.OpusDecoder.Decode(audioMsg.OpusPCM, msgPCM)
		if err != nil {
			clog.Warnf("opus decode failed: %v", err)
			continue
		}
		clog.Tracef("opus decoded %d samples", len(msgPCM))
		chunk := values.AudioChunk{
			BasePCM:     msgPCM,
			Contributor: thisClient.ClientID,
			Timestamp:   audioMsg.Timestamp,
		}
		clog.Trace("adding chunk to room buffer")
		conversion.AddChunk(chunk, thisRoom)
	}
}
