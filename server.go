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
	"github.com/sirupsen/logrus"
	_ "github.com/toucan/toucan-calls/utils"
	"github.com/toucan/toucan-calls/utils/conversion"
	"github.com/toucan/toucan-calls/utils/encrypt"
	"github.com/toucan/toucan-calls/utils/values"
)

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


var (
  roomMu = &sync.Mutex{}
  roomCond = sync.NewCond(roomMu)
  serverRooms []*values.Room = make([]*values.Room,0)
)

func main() {
  host := os.Getenv("HOST"); if host == "" { host = "127.0.0.1" }
  port := os.Getenv("PORT"); if port == "" { port = "3000" }
  logrus.Debugln("Generating ECC keys")
  PrivateKey, err := ecies.GenerateKey();if err != nil { logrus.Fatalf("Failed to generate ECC keys: %v\n",err); }
  logrus.Debugf("Resolving address: %s:%s\n",host,port)
  addr, err := sctp.ResolveSCTPAddr("sctp", fmt.Sprintf("%s:%s",host,port)); if err != nil { logrus.Fatalf("Failed to resolve address: %v\n",err); }
  if values.FECEncoderError != nil {
    logrus.Fatalf("Error in generating FEC Encoder: %v\n",values.FECEncoderError)
  }
  logrus.Debugln("Starting Server")
  listener, err := sctp.ListenSCTP("sctp",addr); if err != nil { logrus.Fatalf("Failed to start the server: %v\n",err) }
  defer listener.Close()
  logrus.Infof("Started server at %s:%s",host,port)
  ctx,cancel := context.WithCancel(context.Background())
  defer cancel()
  go func() {
    sigChan := make(chan os.Signal,1)
    signal.Notify(sigChan,os.Interrupt,syscall.SIGTERM)
    <-sigChan
    logrus.Info("Shutting down the server..")
    cancel()
    //os.Exit(0)
  }()
  go handleWriteToClients(ctx)
  for {
    conn, err := listener.AcceptSCTP(); if err != nil { logrus.Errorf("Failed to create connection: %v\n",err) }
    logrus.Debugf("Connection created with: %s\n",conn.RemoteAddr().String())
    go handleClient(conn,PrivateKey)
  }
}

func handleRemoveClient(con *values.Client,room_uuid uuid.UUID) {
  roomMu.Lock()
  defer roomMu.Unlock()
  exist_room_id := -1
  for i,room := range serverRooms {
    if room_uuid == room.RoomID {
      exist_room_id = i
      break
    }
  }
  if exist_room_id > -1 {
    logrus.Debugf("Found the room of client %s\n",con.ClientID.String())
  } else {
    logrus.Error("Room does not exist")
    return
  }
  exist_client := -1
  for i,client := range serverRooms[exist_room_id].Clients {
    if con.ClientID == client {
      exist_client = i
      break
    }
  }
  if exist_client > -1 {
    logrus.Debugf("Found the client %s in room %s\n",con.ClientID.String(),serverRooms[exist_room_id].RoomID.String())
  } else {
    logrus.Errorf("Client %s does not exist in room %s",con.ClientID.String(),serverRooms[exist_room_id].RoomID.String())
    return
  }
  if len(serverRooms[exist_room_id].Clients) == 1 {
		logrus.Debugf("Room %s had only one client. Removing the room.", serverRooms[exist_room_id].RoomID.String())
    if exist_room_id >= 0 && exist_room_id < len(serverRooms) {
      if len(serverRooms) > 1 {
        serverRooms = append(serverRooms[:exist_room_id], serverRooms[exist_room_id+1:]...)
      } else {
        serverRooms = []*values.Room{}
      }
    }
	} else {
    logrus.Debugf("Removing client %s from room %s\n",con.ClientID.String(), serverRooms[exist_room_id].RoomID.String())
		serverRooms[exist_room_id].Clients = append(serverRooms[exist_room_id].Clients[:exist_client], serverRooms[exist_room_id].Clients[exist_client+1:]...)
	}
}

func handleClient(con *sctp.SCTPConn,PrivateKey *ecies.PrivateKey) {
  // Sending Public Key as Hex 
  logrus.Debugf("Sending public key to %s\n",con.RemoteAddr().String())
  _,err := con.Write([]byte(PrivateKey.PublicKey.Hex(true))); if err != nil { logrus.Errorf("Error in sending the public key to %s: %v\n",con.RemoteAddr().String(),err);return }

  // Here we read the encrypted AES Secret from the client and decrypt using ECC private key
  logrus.Debugf("Reading encrypted key from %s\n",con.RemoteAddr().String())
  AESEnc := make([]byte,256)
  key_size,err := con.Read(AESEnc); if err != nil { logrus.Errorf("Error in reading key from %s: %v\n",con.RemoteAddr().String(),err);return }
  logrus.Debugf("Decrypting key from %s\n",con.RemoteAddr().String())
  values.AESKey,err = ecies.Decrypt(PrivateKey,AESEnc[:key_size]); if err != nil { logrus.Errorf("Error in decrypting AES key from %s: %v\n",con.RemoteAddr().String(),err);return }
  
  // Sending ACK to the client to indicate that we managed to decrypt the key and managed to create AES object
  logrus.Debugf("Sending ACK to %s\n",con.RemoteAddr().String())
  _,err = con.Write(values.ACKMessage); if err != nil { logrus.Errorf("Error in sending ACK to %s: %v\n",con.RemoteAddr().String(),err);return }
  
  // Getting Room ID from the Client and categorizing them.
  logrus.Debugf("Getting Room ID from client %s\n",con.RemoteAddr().String())
  room_id_dec := make([]byte,128)
  room_id_size,err := con.Read(room_id_dec); if err != nil { logrus.Errorf("Error in reading Room ID from %s: %v\n",con.RemoteAddr().String(),err) }
  room_id,err := encrypt.DecryptAES(room_id_dec[:room_id_size],values.AESKey); if err != nil { logrus.Errorf("Error in decrypting Room ID from %s: %v\n",con.RemoteAddr().String(),err) }
  room_uuid,err := uuid.Parse(string(room_id));if err != nil { logrus.Errorf("Error in parsing Room ID from %s: %v\n",con.RemoteAddr().String(),err);return }

  // Handling rooms for the clients
  roomMu.Lock()
  exist_room_id := -1
  for i,room := range serverRooms {
    if (room_uuid == room.RoomID) {
      exist_room_id = i
      break
    }
  }
  thisClient := values.Client {
    Network: con,
    AESkey: values.AESKey,
    ClientID: uuid.New(),
  }
  var thisRoom *values.Room
  if (exist_room_id > -1) {
    logrus.Debugf("Found Room for client %s\n",con.RemoteAddr().String())
    serverRooms[exist_room_id].Clients = append(serverRooms[exist_room_id].Clients, thisClient.ClientID)
    thisRoom = serverRooms[exist_room_id]
    if (len(thisRoom.AudioBuf.Buffer)) == 0 {
      thisRoom.AudioBuf.Buffer = make([]*values.AudioChunk, 0)
    }
  } else {
    logrus.Debugf("Creating a room for client %s\n",con.RemoteAddr().String())
    thisRoom = &values.Room {
      RoomID: room_uuid,
      Clients: make([]uuid.UUID, 0),
      AudioBuf: &values.AudioBuffer{
        Buffer: make([]*values.AudioChunk, 0), 
      },
    }
    thisRoom.Clients = append(thisRoom.Clients, thisClient.ClientID)
    serverRooms = append(serverRooms, thisRoom)
    roomCond.Signal()
  }
  roomMu.Unlock()
  values.ClientList = append(values.ClientList, thisClient)
  for {
    msg_buf := make([]byte,1024*100)
    if con.RemoteAddr() == nil { break }
    msg_size,err := con.Read(msg_buf); if err != nil { logrus.Errorf("Error in reading input from %s: %v\n",con.RemoteAddr().String(),err) }
    if msg_size > 3 {
      msg_enc,err := encrypt.DecryptAES(msg_buf[:msg_size],thisClient.AESkey); if err != nil { logrus.Errorf("Error in decrypting the input from %s: %v\n",con.RemoteAddr().String(),err) }
      msg_dec,_,err := values.FECEncoder.DecodeData(msg_enc); if err != nil { logrus.Errorf("Error in decoding incoming data from %s: %v\n",con.RemoteAddr().String(),err) }
      var msg_unmarshel values.Audio
      if err := json.Unmarshal(msg_dec,&msg_unmarshel); err != nil { logrus.Errorf("Error in Unmarshalling the data from %s: %v\n",con.RemoteAddr().String(),err) }
      count := values.ClientchannelCount * values.ClientframesPerBuffer * values.ClientRate / 1000
      msg_pcm := make([]int16,count)
      values.OpusDecoder.Decode(msg_unmarshel.OpusPCM,msg_pcm)
      //if !issues { logrus.Warnf("There are errors in the incoming data from %s\n",con.RemoteAddr().String()) } 
      thisChunk := values.AudioChunk {
        BasePCM: msg_pcm,
        Contributor: thisClient.ClientID,
        Timestamp: msg_unmarshel.Timestamp,
      }
      conversion.AddChunk(thisChunk,*thisRoom)  
    } else {
      defer handleRemoveClient(&thisClient,room_uuid)
      defer logrus.Debugf("Recieved EXT Signal from client %s",thisClient.Network.RemoteAddr().String())
      if string(msg_buf[:msg_size]) == "EXT" { break }
    }
  }
}

func handleWriteToClients(ctx context.Context) {
  var activeRooms sync.Map
  roomMu.Lock()
  if len(serverRooms) == 0 {
    logrus.Debugf("Waiting for clients..")
    roomCond.Wait()
  }
  roomMu.Unlock()
  for {
    roomMu.Lock()
    select {
    case <- ctx.Done():
      logrus.Debug("Context cancelled.Stopping the writers..")
      return
    default:
      if len(serverRooms) == 0 { 
        logrus.Debugf("Waiting for a new client..")
        roomCond.Wait()
      } else {
        for _,room := range serverRooms {
          if _, exists := activeRooms.Load(room.RoomID); !exists {
            activeRooms.Store(room.RoomID,struct {}{})
            go func(room *values.Room,ctx context.Context) {
              defer activeRooms.Delete(room.RoomID)
              for {
                room.Mu.Lock()
                select {
                case <- ctx.Done():
                  fmt.Println(room.Clients)
                  logrus.Debugf("Context cancelled.Stopping the writer for RoomID: %s",room.RoomID.String())
                  return
                default:
                  if len(room.Clients) == 0 {
                    logrus.Debug("There are no clients in the room.")
                    return
                  } else {
                    fmt.Println(room.Clients)
                    time.Sleep(1*time.Second)
                    room.AudioBuf.Mu.Lock()
                    fmt.Println(len(room.AudioBuf.Buffer))
                    room.AudioBuf.Mu.Unlock()
                  }
                }
                room.Mu.Unlock()
              }
            }(room,ctx)
          }
        }
      }
    }
    roomMu.Unlock()
  }
}
