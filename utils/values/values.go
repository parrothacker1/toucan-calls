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
  ClientID uuid.UUID
  Network *sctp.SCTPConn
  AESkey  []byte
}

type Audio struct {
  OpusPCM []byte `json:"pcm"`
  Timestamp time.Time `json:"time"`
}

type AudioChunk struct {
  BasePCM []int16
  Contributor uuid.UUID // client's UUID
  Timestamp time.Time
}

type AudioBuffer struct {
  Mu sync.Mutex
  Buffer []*AudioChunk
}

type Room struct {
  AudioBuf *AudioBuffer
  Clients []uuid.UUID // client's UUID
  RoomID uuid.UUID
  Mu sync.Mutex
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
var ClientList = make([]Client,10)
