package values

import (
	"sync"
	"time"

	ecies "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/utils"
	"gopkg.in/hraban/opus.v2"
)

var ACKMessage []byte = []byte("ACK");
var PublicKey *ecies.PublicKey;
var AESKey []byte;

type Client struct {
  Network *sctp.SCTPConn
  AESkey  []byte
}

type AudioChunk struct {
  BasePCM []int16
  Overlay map[*Client][]int16
  RefCounter int
  Timestamp time.Time
}

type AudioBuffer struct {
  Mu sync.Mutex
  Buffer []*AudioChunk
}

type Room struct {
  AudioBuf *AudioBuffer
  Clients []*Client
  RoomID uuid.UUID
}

const (
	ClientRate = 48000
	ClientframesPerBuffer = 480*6
	ClientchannelCount   = 1
)

var ClientAudioBuffer = make(chan []int16,30)

var FECEncoder,FECEncoderError = utils.NewEncoder(6,3)
var OpusEncoder,OpusEncoderError = opus.NewEncoder(ClientRate,ClientchannelCount,opus.AppVoIP)
var OpusDecoder,OpusDecoderError = opus.NewDecoder(ClientRate,ClientchannelCount)
