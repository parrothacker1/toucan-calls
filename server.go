package main

import (
	"fmt"
	"os"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	"github.com/sirupsen/logrus"
	_ "github.com/toucan/toucan-calls/utils"
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


var serverRooms []values.Room = make([]values.Room,0)

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
  for {
    conn, err := listener.AcceptSCTP(); if err != nil { logrus.Errorf("Failed to create connection: %v\n",err) }
    logrus.Debugf("Connection created with: %s\n",conn.RemoteAddr().String())
    go handleClient(conn,PrivateKey)
  }
}

func handleRemoveClient(con *sctp.SCTPConn,room_uuid uuid.UUID) {
  exist_room_id := -1
  for i,room := range serverRooms {
    if room_uuid == room.RoomID {
      exist_room_id = i
      break
    }
  }
  if exist_room_id > -1 {
    logrus.Debugf("Found the room of client %s\n",con.RemoteAddr().String())
  } else {
    logrus.Error("Room does not exist")
    return
  }
  exist_client := -1
  for i,client := range serverRooms[exist_room_id].Clients {
    if con.RemoteAddr().Network() == client.Network.RemoteAddr().Network() {
      exist_client = i
      break
    }
  }
  if exist_client > -1 {
    logrus.Debugf("Found the client %s in room %s\n",con.RemoteAddr().String(),serverRooms[exist_room_id].RoomID.String())
  } else {
    logrus.Errorf("Client %s does not exist in room %s",con.RemoteAddr().String(),serverRooms[exist_room_id].RoomID.String())
    return
  }
  if len(serverRooms[exist_room_id].Clients) == 1 {
		logrus.Debugf("Room %s had only one client. Removing the room.", serverRooms[exist_room_id].RoomID.String())
    if exist_room_id >= 0 && exist_room_id < len(serverRooms) {
      if len(serverRooms) > 1 {
        serverRooms = append(serverRooms[:exist_room_id], serverRooms[exist_room_id+1:]...)
      } else {
        serverRooms = []values.Room{}
      }
    }
	} else {
    logrus.Debugf("Removing client %s from room %s\n",con.RemoteAddr().String(), serverRooms[exist_room_id].RoomID.String())
		serverRooms[exist_room_id].Clients = append(serverRooms[exist_room_id].Clients[:exist_client], serverRooms[exist_room_id].Clients[exist_client+1:]...)
	}
}

func handleClient(con *sctp.SCTPConn,PrivateKey *ecies.PrivateKey) {
  defer con.Close()

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
  defer handleRemoveClient(con,room_uuid)

  // Handling rooms for the clients
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
  }
  if (exist_room_id > -1) {
    logrus.Debugf("Found Room for client %s\n",con.RemoteAddr().String())
    serverRooms[exist_room_id].Clients = append(serverRooms[exist_room_id].Clients, &thisClient)
  } else {
    logrus.Debugf("Creating a room for client %s\n",con.RemoteAddr().String())
    thisRoom := values.Room {
      RoomID: room_uuid,
      Clients: make([]*values.Client, 0),
      AudioBuf: &values.AudioBuffer{
        Buffer: make([]*values.AudioChunk, 0), 
      },
    }
    thisRoom.Clients = append(thisRoom.Clients, &thisClient)
    serverRooms = append(serverRooms, thisRoom)
  }
  for {
    msg_buf := make([]byte,1024*100)
    if con.RemoteAddr() == nil { break }
    msg_size,err := con.Read(msg_buf); if err != nil { logrus.Errorf("Error in reading input from %s: %v\n",con.RemoteAddr().String(),err) }
    if msg_size > 3 {
      msg_enc,err := encrypt.DecryptAES(msg_buf[:msg_size],thisClient.AESkey); if err != nil { logrus.Errorf("Error in decrypting the input from %s: %v\n",con.RemoteAddr().String(),err) }
      msg_dec,_,err := values.FECEncoder.DecodeData(msg_enc); if err != nil { logrus.Errorf("Error in decoding incoming data from %s: %v\n",con.RemoteAddr().String(),err) }
      //if !issues { logrus.Warnf("There are errors in the incoming data from %s\n",con.RemoteAddr().String()) }
      /*for key,value := range values.Storage {
        if key != con && value.RoomID == values.Storage[con].RoomID {
          // broadcasting that message to everyone
          if _, exists := values.Storage[key]; exists {
            msg_enc,err = values.FECEncoder.EncodeData(msg_dec); if err != nil { logrus.Errorf("Error in encoding data to be sent to %s: %v\n",key.RemoteAddr().String(),err) }
            msg_to_snd,err := encrypt.EncryptAES(msg_enc,value.AESkey);if err != nil { logrus.Errorf("Error in encrypting data to be sent to %s: %v\n",key.RemoteAddr().String(),err) }
            _,err = key.Write(msg_to_snd)
            if err != nil { logrus.Errorf("Error in sending message from %s to %s: %v\n",con.RemoteAddr().String(),key.RemoteAddr().String(),err) }
          }
        }
      }*/
    } else {
      defer logrus.Debugf("Recieved EXT Signal from client %s",con.RemoteAddr().String())
      if string(msg_buf[:msg_size]) == "EXT" { break }
    }
  }
}
