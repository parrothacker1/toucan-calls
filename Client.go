package main

import (
	"bufio"
	"crypto/rand"
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

func main() {
  host := os.Getenv("HOST"); if host == "" { host = "127.0.0.1" }
  port := os.Getenv("PORT"); if port == "" { port = "3000" }
  logrus.Debug("Generating AES Key")
  values.AESKey = make([]byte, 32)
  _,err := rand.Read(values.AESKey);if err != nil { logrus.Fatalf("Error in generating AES Key: %v\n",err) }
  logrus.Debugf("Resolving address %s:%s\n",host,port)
  addr, err := sctp.ResolveSCTPAddr("sctp",fmt.Sprintf("%s:%s",host,port)); if err != nil { logrus.Fatalf("Failed to resolve address: %v\n",err) }
  logrus.Debugf("Connecting to server %s:%s\n",host,port)
  conn, err := sctp.DialSCTP("sctp",nil,addr); if err != nil { logrus.Fatalf("Failed to connect to server: %v\n",err) }
  logrus.Infof("Connected to server at %s",conn.RemoteAddr().String())

  // Recieving the ECC Public key and making ECC Object out of it
  pubKeyBuffer := make([]byte,128)
  n, err := conn.Read(pubKeyBuffer); if err != nil { logrus.Fatalf("Failed to read ECC public key from %s: %v\n",conn.RemoteAddr().String(),err) }
  pubKeyHex := string(pubKeyBuffer[:n])
  values.PublicKey, err = ecies.NewPublicKeyFromHex(pubKeyHex); if err != nil { logrus.Fatalf("Error in making public key from %s: %v\n",conn.RemoteAddr().String(),err) }
  aesKey,err := ecies.Encrypt(values.PublicKey,values.AESKey);if err != nil { logrus.Fatalf("Error in generating encrytped AES: %v\n") }
  _,err = conn.Write(aesKey)
  ackMessage := make([]byte,128)
  n,err = conn.Read(ackMessage); if err != nil { logrus.Fatalf("Server %s didn't send ACK to client.",conn.RemoteAddr().String()) }
  if string(ackMessage[:n]) == string(values.ACKMessage) { logrus.Infof("Successful connection with %s",conn.RemoteAddr().String()) }

  // Chat room .. create / join
  reader := bufio.NewReader(os.Stdin)
  fmt.Print("1.Create a room\n2.Join a room\nOption -> ")
  var input,room_id string;
  for {
    input, err = reader.ReadString('\n'); if err != nil { logrus.Errorf("Error in reading the input: %v\n",err) }
    input = input[:len(input)-1]
    if input != "1" && input != "2" { logrus.Error("Wrong Option.Try again") } else { break }
  }
  if input == "1" { room_id = uuid.New().String();logrus.Infof("The Room ID is %s",room_id) } else { 
    for {
      fmt.Print("Enter the Room ID: ")
      room_id,err = reader.ReadString('\n');if err != nil { logrus.Errorf("Error in reading Room ID: %v\n",err) }
      room_id = string(room_id[:len(room_id)-1])
      _,err = uuid.Parse(room_id); if err != nil { logrus.Errorf("The given UUID is invalid: %v\n",err) } else { break }
    }
  }
  room_id_enc,err := encrypt.EncryptAES([]byte(room_id),values.AESKey);if err != nil { logrus.Fatalf("The UUID cannot be encrypted: %v\n",err) }
  _,err = conn.Write(room_id_enc);if err != nil { logrus.Fatalf("Error in sending room ID to server %s: %v\n",conn.RemoteAddr().String(),err) }
  time.Sleep(20*time.Second)
  text,err := encrypt.EncryptAES([]byte("testing_is_in_veins"),values.AESKey)
  _,err = conn.Write(text)
  msg_buf := make([]byte,1024)
  n,err = conn.Read(msg_buf)
  msg,err := encrypt.DecryptAES(msg_buf[:n],values.AESKey);
  fmt.Println(string(msg))
  msg_buf = make([]byte,1024)
  n,err = conn.Read(msg_buf)
  msg,err = encrypt.DecryptAES(msg_buf[:n],values.AESKey);
  fmt.Println(string(msg))
  _,err = conn.Write([]byte("EXT"))
  conn.Close()
}
