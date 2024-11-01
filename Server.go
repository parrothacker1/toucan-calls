package main

import (
	"fmt"
	"os"
	_ "reflect"

	ecies "github.com/ecies/go/v2"
	"github.com/ishidawataru/sctp"
	"github.com/sirupsen/logrus"
	"github.com/toucan/toucan-calls/utils"
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

var ACKMessage []byte = []byte("ACK");
var AESKey []byte = make([]byte,256);

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
  // Sending Public Key as Hex 
  logrus.Debugf("Sending public key to %s\n",con.RemoteAddr().String())
  _,err := con.Write([]byte(PrivateKey.PublicKey.Hex(true))); if err != nil { logrus.Errorf("Error in sending the public key to %s: %v\n",con.RemoteAddr().String(),err);return }

  // Here we read the encrypted AES Secret from the client and decrypt using ECC private key
  logrus.Debugf("Reading encrypted key from %s\n",con.RemoteAddr().String())
  key_size,err := con.Read(AESKey); if err != nil { logrus.Errorf("Error in reading key from %s: %v\n",con.RemoteAddr().String(),err);return }
  logrus.Debugf("Decrypting key from %s\n",con.RemoteAddr().String())
  aesKey,err := ecies.Decrypt(PrivateKey,AESKey[:key_size]); if err != nil { logrus.Errorf("Error in decrypting AES key from %s: %v\n",con.RemoteAddr().String(),err);return }
  _,err = utils.NewAES(aesKey); if err != nil { logrus.Errorf("Error in creating a AES object with the key from %s: %v\n",con.RemoteAddr().String(),err);return }

  // Sending ACK to the client to indicate that we managed to decrypt the key and managed to create AES object
  logrus.Debugf("Sending ACK to %s\n",con.RemoteAddr().String())
  _,err = con.Write(ACKMessage); if err != nil { logrus.Errorf("Error in sending ACK to %s: %v\n",con.RemoteAddr().String(),err);return }
  
  // Starting a full duplex communication and adding FEC to each message here onwards
  _ = utils.NewDuplex(con)
  _, err = utils.NewEncoder(4,2)
}
