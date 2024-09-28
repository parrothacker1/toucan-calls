package main

import (
  "fmt"
  "log"

  "github.com/ishidawataru/sctp"
  "github.com/toucan/toucan-calls/utils"
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
  duplex := utils.NewDuplex(conn)
  go duplex.ReadLoop()
  duplex.WriteLoop([]byte("Nigga fuck u"))
  select {}
}
