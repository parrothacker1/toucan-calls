package values

import (
	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/utils"
	"gopkg.in/hraban/opus.v2"
)

var ACKMessage []byte = []byte("ACK");
var PublicKey *ecies.PublicKey;
var AESKey []byte;

type StorageValue struct {
  RoomID uuid.UUID
  AESkey  []byte
};

const (
	ClientRate = 48000
	ClientframesPerBuffer = 480*6
	ClientchannelCount   = 1
)

var Storage = make(map[*sctp.SCTPConn]StorageValue)

var ClientAudioBuffer = make(chan []int16,30)

var FECEncoder,FECEncoderError = utils.NewEncoder(6,3)
var OpusEncoder,OpusEncoderError = opus.NewEncoder(ClientRate,ClientchannelCount,opus.AppVoIP)
var OpusDecoder,OpusDecoderError = opus.NewDecoder(ClientRate,ClientchannelCount)
