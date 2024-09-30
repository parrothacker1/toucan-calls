package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/utils"
)

func main() {
  host := os.Getenv("HOST")
  port := os.Getenv("PORT")
  if (host == "") {
    host = "127.0.0.1"
  }
  if (port == "") {
    port = "3000"
  }
  log.Println("Generating the ECC keys")
  ecc_obj,err := utils.GenerateECCKeys()
  if err != nil {
    log.Fatalf("Failed in generating ECC keys")
  }
  addr, err := sctp.ResolveSCTPAddr("sctp",fmt.Sprintf("%s:%s",host,port))
  if err != nil {
    log.Fatalf("Failed to resolve address: %v\n",err)
  }
  listener, err := sctp.ListenSCTP("sctp",addr)
  if err != nil {
    log.Fatalf("Failed to start server: %v\n",err)
  }
  defer listener.Close()
  fmt.Println("Started Server at ",port)

  for {
    conn, err := listener.AcceptSCTP()
    if err != nil {
      log.Printf("Failed to create a connection: %v\n",err)
    }
    fmt.Println("Client Connected: ",conn.RemoteAddr().String())
    go handleClient(conn,ecc_obj)
  }

  select {}
}

func handleClient(conn *sctp.SCTPConn,ecc *utils.ECC) {
  defer conn.Close()
  var wg sync.WaitGroup
  wg.Add(2)
  publicBytes := append(ecc.PublicKey.X.Bytes(),ecc.PublicKey.Y.Bytes()...)
  _,err := conn.Write(publicBytes)
  if err != nil {
    log.Println("Error in sending ECC key")
    return
  }
  fmt.Println("ECC key sent to client")
  encryptKey := make([]byte,256)
  _, err = conn.Read(encryptKey)
  if err != nil {
    log.Println("Error in reading key")
    return
  }
  aesKey, err := ecc.DecryptECC(encryptKey)
  if err != nil {
    log.Println("Error in decrypting the AES Key.")
    return
  }
  ackMessage := []byte("ACK")
  _, err = conn.Write(ackMessage)
  if err != nil {
    log.Println("Error in sending ack to client")
    return
  }
  fmt.Println("Sent ACK to client")

  _,err = utils.NewAES(aesKey)
  if err != nil {
    log.Println("Unable to generate new AES object")
    return
  }
  duplex := utils.NewDuplex(conn)
  go duplex.ReadLoop()
  fec, err := utils.NewEncoder(10, 3)
	if err != nil {
    log.Println("Error in creating Encoder")
    return
	}
	data, err := fec.EncodeData([]byte("Thanks from server"))
	if err != nil {
		log.Println("Error in encoding the data")
	}
	fmt.Printf("%v\n", string(data))
	go duplex.WriteLoop(data)

	wg.Wait()
}
