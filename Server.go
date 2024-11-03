package main

import (
	"fmt"
	"os"

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

func main() {
  host := os.Getenv("HOST"); if host == "" { host = "127.0.0.1" }
  port := os.Getenv("PORT"); if port == "" { port = "3000" }
  logrus.Debugln("Generating ECC keys")
  PrivateKey, err := ecies.GenerateKey();if err != nil { logrus.Fatalf("Failed to generate ECC keys: %v\n",err); }
  logrus.Debugf("Resolving address: %s:%s\n",host,port)
  addr, err := sctp.ResolveSCTPAddr("sctp", fmt.Sprintf("%s:%s",host,port)); if err != nil { logrus.Fatalf("Failed to resolve address: %v\n",err); }
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

func handleClient(con *sctp.SCTPConn,PrivateKey *ecies.PrivateKey) {
  defer con.Close()
  defer delete(values.Storage,con)
  defer logrus.Debugf("Recieved EXT Signal from client %s",con.RemoteAddr().String())

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
  room_id,err := encrypt.DecryptAES(room_id_dec[:room_id_size],values.AESKey); if err != nil { logrus.Errorf("Error in decrypting Room IF from %s: %v\n",con.RemoteAddr().String(),err) }
  room_uuid,err := uuid.Parse(string(room_id));if err != nil { logrus.Errorf("Error in parsing Room ID from %s: %v\n",con.RemoteAddr().String(),err) }
  values.Storage[con] = values.StorageValue { 
    RoomID : room_uuid,
    AESkey : values.AESKey,
  }

  for {
    // reading input from the client 
    msg_buf := make([]byte,1024)
    if con.RemoteAddr() == nil {
      break
    }
    msg_size,err := con.Read(msg_buf); if err != nil { logrus.Errorf("Error in reading input from %s: %v\n",con.RemoteAddr().String(),err) }
    if msg_size > 3 {
      msg,err := encrypt.DecryptAES(msg_buf[:msg_size],values.Storage[con].AESkey); if err != nil { logrus.Errorf("Error in decrypting the input from %s: %v\n",con.RemoteAddr().String(),err) }
      for key,value := range values.Storage {
        if key != con && value.RoomID == values.Storage[con].RoomID {
          msg_to_snd,err := encrypt.EncryptAES(msg,value.AESkey); if err != nil { logrus.Errorf("Error in encrypting message from %s for %s: %v\n",con.RemoteAddr().String(),key.RemoteAddr().String(),err) }
          if _, exists := values.Storage[key]; exists {
            _,err = key.Write(msg_to_snd); if err != nil { logrus.Errorf("Error in sending messgae from %s to %s: %v\n",con.RemoteAddr().String(),key.RemoteAddr().String(),err) }
          }
        }
      }
    } else {
      if string(msg_buf[:msg_size]) == "EXT" {
        break
      }
    }
  }

  // FEC -> AES -> Broadcasting
}
