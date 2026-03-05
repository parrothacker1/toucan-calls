package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"

	"github.com/toucan/toucan-calls/internal/utils/conversion"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/logger"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

var (
	roomMu   = &sync.Mutex{}
	roomCond = sync.NewCond(roomMu)

	serverRooms []*values.Room = make([]*values.Room, 0)

	log = logger.NewLogger(logger.LoggerOpts{
		Filename: "",
	})
)

func main() {

	host := os.Getenv("HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.WithFields(logger.Fields{
		"host": host,
		"port": port,
	}).Info("starting toucan server")

	log.Debug("generating ECC keys")

	PrivateKey, err := ecies.GenerateKey()
	if err != nil {
		log.Fatalf("failed to generate ECC keys: %v", err)
	}

	addr, err := sctp.ResolveSCTPAddr("sctp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		log.Fatalf("failed to resolve address: %v", err)
	}

	if values.FECEncoderError != nil {
		log.Fatalf("FEC encoder initialization error: %v", values.FECEncoderError)
	}

	listener, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}

	defer listener.Close()

	log.Infof("server listening on %s:%s", host, port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {

		sigChan := make(chan os.Signal, 1)

		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		<-sigChan

		log.Warn("shutdown signal received")
		log.Events.Reset(true)
		cancel()

	}()

	go handleWriteToClients(ctx)

	for {

		conn, err := listener.AcceptSCTP()

		if err != nil {
			log.WithField("error", err).
				Error("failed to accept connection")
			continue
		}

		log.WithField("remote", conn.RemoteAddr().String()).
			Debug("new connection accepted")

		go handleClient(conn, PrivateKey)

	}
}

func handleRemoveClient(con *values.Client, room_uuid uuid.UUID) {

	roomMu.Lock()
	defer roomMu.Unlock()

	exist_room_id := -1

	for i, room := range serverRooms {
		if room_uuid == room.RoomID {
			exist_room_id = i
			break
		}
	}

	if exist_room_id == -1 {
		log.Error("room does not exist while removing client")
		return
	}

	exist_client := -1

	for i, client := range serverRooms[exist_room_id].Clients {
		if con.ClientID == client {
			exist_client = i
			break
		}
	}

	if exist_client == -1 {

		log.WithField("client_id", con.ClientID.String()).
			Error("client not found in room")

		return
	}

	if len(serverRooms[exist_room_id].Clients) == 1 {

		log.WithField("room_id", serverRooms[exist_room_id].RoomID.String()).
			Debug("removing empty room")

		if len(serverRooms) > 1 {
			serverRooms = append(serverRooms[:exist_room_id], serverRooms[exist_room_id+1:]...)
		} else {
			serverRooms = []*values.Room{}
		}

	} else {

		log.WithFields(logger.Fields{
			"room_id":   serverRooms[exist_room_id].RoomID.String(),
			"client_id": con.ClientID.String(),
		}).Debug("removing client from room")

		serverRooms[exist_room_id].Clients =
			append(serverRooms[exist_room_id].Clients[:exist_client],
				serverRooms[exist_room_id].Clients[exist_client+1:]...)
	}
}

func handleClient(con *sctp.SCTPConn, PrivateKey *ecies.PrivateKey) {

	remote := con.RemoteAddr().String()

	log.WithField("remote", remote).
		Debug("sending server public key")

	_, err := con.Write([]byte(PrivateKey.PublicKey.Hex(true)))
	if err != nil {
		log.WithField("remote", remote).
			Errorf("failed sending public key: %v", err)
		return
	}

	AESEnc := make([]byte, 256)

	key_size, err := con.Read(AESEnc)
	if err != nil {
		log.WithField("remote", remote).
			Errorf("failed reading AES key: %v", err)
		return
	}

	values.AESKey, err = ecies.Decrypt(PrivateKey, AESEnc[:key_size])
	if err != nil {
		log.WithField("remote", remote).
			Errorf("AES decrypt failed: %v", err)
		return
	}

	log.WithField("remote", remote).
		Debug("AES session key established")

	_, err = con.Write(values.ACKMessage)
	if err != nil {
		log.WithField("remote", remote).
			Errorf("failed sending ACK: %v", err)
		return
	}

	room_id_dec := make([]byte, 128)

	room_id_size, err := con.Read(room_id_dec)
	if err != nil {
		log.WithField("remote", remote).
			Errorf("failed reading room id: %v", err)
		return
	}

	room_id, err := encrypt.DecryptAES(room_id_dec[:room_id_size], values.AESKey)
	if err != nil {
		log.WithField("remote", remote).
			Errorf("room id decrypt failed: %v", err)
		return
	}

	room_uuid, err := uuid.Parse(string(room_id))
	if err != nil {
		log.WithField("remote", remote).
			Errorf("invalid room uuid: %v", err)
		return
	}

	roomMu.Lock()

	exist_room_id := -1

	for i, room := range serverRooms {
		if room_uuid == room.RoomID {
			exist_room_id = i
			break
		}
	}

	thisClient := values.Client{
		Network:  con,
		AESkey:   values.AESKey,
		ClientID: uuid.New(),
	}

	var thisRoom *values.Room

	if exist_room_id > -1 {

		thisRoom = serverRooms[exist_room_id]

		thisRoom.Clients =
			append(thisRoom.Clients, thisClient.ClientID)

		log.WithField("room_id", room_uuid.String()).
			Debug("client joined room")

	} else {

		thisRoom = &values.Room{
			RoomID:  room_uuid,
			Clients: []uuid.UUID{},
			AudioBuf: &values.AudioBuffer{
				Buffer: []*values.AudioChunk{},
			},
		}

		thisRoom.Clients =
			append(thisRoom.Clients, thisClient.ClientID)

		serverRooms = append(serverRooms, thisRoom)

		roomCond.Signal()

		log.WithField("room_id", room_uuid.String()).
			Info("created new room")

	}

	roomMu.Unlock()

	values.ClientList = append(values.ClientList, thisClient)

	for {

		msg_buf := make([]byte, 1024*100)

		msg_size, err := con.Read(msg_buf)

		if err != nil {

			log.WithField("remote", remote).
				Errorf("read error: %v", err)

			break
		}

		if msg_size > 3 {

			msg_enc, _ := encrypt.DecryptAES(msg_buf[:msg_size], thisClient.AESkey)

			msg_dec, _, _ := values.FECEncoder.DecodeData(msg_enc)

			var msg_unmarshal values.Audio

			json.Unmarshal(msg_dec, &msg_unmarshal)

			count := values.ClientchannelCount *
				values.ClientframesPerBuffer *
				values.ClientRate / 1000

			msg_pcm := make([]int16, count)

			values.OpusDecoder.Decode(msg_unmarshal.OpusPCM, msg_pcm)

			thisChunk := values.AudioChunk{
				BasePCM:     msg_pcm,
				Contributor: thisClient.ClientID,
				Timestamp:   msg_unmarshal.Timestamp,
			}

			conversion.AddChunk(thisChunk, thisRoom)

		} else {

			defer handleRemoveClient(&thisClient, room_uuid)

			if string(msg_buf[:msg_size]) == "EXT" {

				log.WithField("client_id", thisClient.ClientID.String()).
					Debug("client disconnected")

				break
			}
		}
	}
}

func handleWriteToClients(ctx context.Context) {

	var activeRooms sync.Map

	roomMu.Lock()

	if len(serverRooms) == 0 {
		log.Debug("waiting for clients...")
		roomCond.Wait()
	}

	roomMu.Unlock()

	for {

		roomMu.Lock()

		select {

		case <-ctx.Done():

			log.Debug("writer shutdown")

			roomMu.Unlock()
			return

		default:

			if len(serverRooms) == 0 {

				log.Debug("waiting for new client")

				roomCond.Wait()

			} else {

				for _, room := range serverRooms {

					if _, exists := activeRooms.Load(room.RoomID); !exists {

						activeRooms.Store(room.RoomID, struct{}{})

						go func(room *values.Room) {

							defer activeRooms.Delete(room.RoomID)

							for {

								room.Mu.Lock()

								if len(room.Clients) == 0 {

									log.WithField("room_id", room.RoomID.String()).
										Debug("room empty stopping writer")

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

		roomMu.Unlock()

	}
}
