package utils

import (
	"fmt"
	"log"
	"time"

	"github.com/ishidawataru/sctp"
)

type Duplex struct {
  Conn *sctp.SCTPConn
}

func NewDuplex(conn *sctp.SCTPConn) *Duplex {
  return &Duplex{
    Conn: conn,
  }
}

func (d *Duplex) ReadLoop() {
  for {
    buffer := make([]byte,1024)
    n, err := d.Conn.Read(buffer)
    if err != nil {
      log.Printf("Error in reading from connection: %v",err)
      return
    }
    message := string(buffer[:n])
    fmt.Println("The message from connection: ",message)
  }
}

func (d *Duplex) WriteLoop(message []byte) {
  for {
    _,err := d.Conn.Write(message)
    if err != nil {
      log.Printf("Error in writing to connection: %v",err)
      return
    }
    //fmt.Println("Message sent")
  }
  time.Sleep(2*time.Second)
}
