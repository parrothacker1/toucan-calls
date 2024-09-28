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
    go handleClient(conn)
  }

  select {}
}

func handleClient(conn *sctp.SCTPConn) {
  defer conn.Close()
  var wg sync.WaitGroup;
  wg.Add(2)
  duplex := utils.NewDuplex(conn)
  go duplex.ReadLoop()
  go duplex.WriteLoop([]byte("Thanks from server"))
  wg.Wait()
}
