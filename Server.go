package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ishidawataru/sctp"
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
}

func handleClient(conn *sctp.SCTPConn) {
  defer conn.Close()
  buffer := make([]byte,1024)
  for  {
    n, err := conn.Read(buffer)
    if fmt.Sprintf("%v",err) != "EOF" && err != nil {
      log.Printf("Failed in reading content from the client: %v",err)
      return
    }
    message := string(buffer[:n])
    fmt.Println("Recieved message: ",message)
    _, err = conn.Write([]byte("Thank You!!"))
    if err != nil {
      log.Printf("Failed in sending the message to client: %v",err)
      return
    }
  }
}
