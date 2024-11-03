package values

import (
	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
)

var ACKMessage []byte = []byte("ACK");
var PublicKey *ecies.PublicKey;
var AESKey []byte;

type StorageValue struct {
  RoomID uuid.UUID
  AESkey  []byte
};

var Storage = make(map[*sctp.SCTPConn]StorageValue)
