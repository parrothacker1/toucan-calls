package main

import (
	"fmt"
	"os"

	"github.com/ishidawataru/sctp"
	"github.com/sirupsen/logrus"
  _ "github.com/toucan/toucan-calls/utils"
  ecies "github.com/ecies/go/v2"
)

var PublicKey *ecies.PublicKey;

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
  logrus.Debugf("Resolving address %s:%s\n",host,port)
  addr, err := sctp.ResolveSCTPAddr("sctp",fmt.Sprintf("%s:%s",host,port)); if err != nil { logrus.Fatalf("Failed to resolve address: %v\n",err) }
  logrus.Debugf("Connecting to server %s:%s\n",host,port)
  conn, err := sctp.DialSCTP("sctp",nil,addr); if err != nil { logrus.Fatalf("Failed to connect to server: %v\n",err) }
  logrus.Infof("Connected to server at %s",conn.RemoteAddr().String())

  // Recieving the ECC Public key and making ECC Object out of it
  pubKeyBuffer := make([]byte,128)
  n, err := conn.Read(pubKeyBuffer); if err != nil { logrus.Fatalf("Failed to read ECC public key from %s: %v\n",conn.RemoteAddr().String(),err) }
  pubKeyHex := string(pubKeyBuffer[:n])
  PublicKey, err = ecies.NewPublicKeyFromHex(pubKeyHex); if err != nil { logrus.Fatalf("Error in making public key from %s: %v\n",conn.RemoteAddr().String(),err) }
  aesKey,err := ecies.Encrypt(PublicKey,[]byte("test"));if err != nil { logrus.Fatalf("Error in generating encrytped AES: %v\n") }
  _,err = conn.Write(aesKey)
  ackMessage := make([]byte,128)
  n,err = conn.Read(ackMessage); if err != nil { logrus.Fatalf("Server %s didn't send ACK to client.",conn.RemoteAddr().String()) }
  if string(ackMessage[:n]) == "ACK" {
    fmt.Println("Successful connection")
  }
}
