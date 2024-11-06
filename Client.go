package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

  _ "time"
	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/gordonklaus/portaudio"
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

const (
	sampleRate     = 44100
	framesPerBuffer = 2205
	channelCount   = 1
)

// Buffer for storing audio segments
var audioBuffer = make(chan []byte, 10)

func main() {
  host := os.Getenv("HOST"); if host == "" { host = "127.0.0.1" }
  port := os.Getenv("PORT"); if port == "" { port = "3000" }
  logrus.Debug("Generating AES Key")
  values.AESKey = make([]byte, 32)
  logrus.Debugf("Initializing PortAudio")
  err := portaudio.Initialize();if err != nil { logrus.Fatalf("Error in initializing portaudio: %v\n",err) }
  defer portaudio.Terminate()
  _,err = rand.Read(values.AESKey);if err != nil { logrus.Fatalf("Error in generating AES Key: %v\n",err) }
  logrus.Debugf("Resolving address %s:%s\n",host,port)
  addr, err := sctp.ResolveSCTPAddr("sctp",fmt.Sprintf("%s:%s",host,port)); if err != nil { logrus.Fatalf("Failed to resolve address: %v\n",err) }
  if values.EncoderError != nil {
    logrus.Fatalf("Error in generating FEC encoder: %v\n",values.EncoderError)
  }
  logrus.Debugf("Connecting to server %s:%s\n",host,port)
  conn, err := sctp.DialSCTP("sctp",nil,addr); if err != nil { logrus.Fatalf("Failed to connect to server: %v\n",err) }
  logrus.Infof("Connected to server at %s",conn.RemoteAddr().String())

  // handling Ctrl + C using signals to avoid closing connection before sending necessary messages
  signals := make(chan os.Signal, 1)
  signal.Notify(signals,os.Interrupt,syscall.SIGTERM)

  go func() {
    <-signals
    logrus.Info("Ctrl+C detected.Stopping the client...")
    conn.Write([]byte("EXT"))
    conn.Close()
    os.Exit(0)
  }()
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

  var wg sync.WaitGroup;
  wg.Add(2)
  go ClientRead(conn)
  go ClientWrite(conn)
  wg.Wait()
}


func ClientRead(con *sctp.SCTPConn) {
  out := make([]int16,2205)
  stream,err := portaudio.OpenDefaultStream(0,1,22050,len(out),out); if err != nil { logrus.Errorf("Error in opening audio stream for output: %v\n",err) }
  defer stream.Close()
  stream.Start()
  defer stream.Stop()
  for {
    buffer := make([]byte,1024*100)
    n,err := con.Read(buffer); if err != nil {logrus.Errorf("Error in reading the message from %s: %v\n",con.RemoteAddr().String(),err);return }
    msg_enc,err := encrypt.DecryptAES(buffer[:n],values.AESKey);if err != nil { logrus.Errorf("Error in decrypting the message from %s: %v\n",con.RemoteAddr().String(),err); return }
    message,_,err := values.Encoder.DecodeData(msg_enc);if err != nil { logrus.Errorf("Error in decoding the message from %s: %v\n",con.RemoteAddr().String(),err); return }
    //if !issues { logrus.Warnf("There are errors in the incoming data from %s.",con.RemoteAddr().String()) }
    count := len(message)/2;if count > len(out) { count = len(out) }
    for i := 0; i < count; i++ {
      out[i] = int16(message[i*2]) | int16(message[i*2+1]) << 8
    }
    if err = stream.Write(); err != nil { logrus.Errorf("Erron in writing stream into output: %v\n",err) }
  }
}


func ClientWrite(con *sctp.SCTPConn) {
  in := make([]int16,2205)
  stream,err := portaudio.OpenDefaultStream(1,0,22050,len(in),in); if err != nil { logrus.Fatalf("Error in opening audio stream for input: %v\n",err) }
  defer stream.Close()
  stream.Start()
  defer stream.Stop()
  for {
    if err := stream.Read(); err != nil { logrus.Errorf("Error in reading from the input stream: %v\n",err) }
    input := int16ToBytes(in)
    data,err := values.Encoder.EncodeData(input);if err != nil { logrus.Errorf("Error in adding FEC to message: %v\n",err);return }
    to_be_snd,err := encrypt.EncryptAES(data,values.AESKey); if err != nil { logrus.Errorf("Error in encrypting the data to be sent to %s: %v\n",con.RemoteAddr().String(),err);return }
    _,err = con.Write(to_be_snd);if err != nil { logrus.Errorf("Error in sending the data to %s: %v\n",con.RemoteAddr().String(),err);return }
  }
}

func int16ToBytes(data []int16) []byte {
  byteBuf := make([]byte,len(data)*2)
  for i,v := range data {
    byteBuf[i*2] = byte(v)
    byteBuf[i*2+1] = byte(v >> 8)
  }
  return byteBuf
}
