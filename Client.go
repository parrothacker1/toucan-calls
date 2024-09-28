package main

import (
  "fmt"
  "log"

  "github.com/ishidawataru/sctp"
)

func main() {
  addr, err := sctp.ResolveSCTPAddr("sctp","127.0.0.1:3000")
  if err != nil {
    log.Fatalf("Failed to resolve address: %v",err)
  }
  conn, err := sctp.DialSCTP("sctp", nil, addr)
  if err != nil {
    log.Fatalf("Failed to cconnect to the server: %v",err)
  }
  defer conn.Close()
  fmt.Println("Connected to the server")
  _, err = conn.Write([]byte("Hello parrot"))
  if err != nil {
    log.Println("Failed in sending the message to server")
  }
  buffer := make([]byte,1024)
  n, err := conn.Read(buffer)
  if err != nil {
    log.Println("Failed in reading the message from server")
  }
  fmt.Println("Messgae from server: ",string(buffer[:n]))
}
