package values

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	ClientRate            = 48000
	ClientframesPerBuffer = 480 * 6
	ClientchannelCount    = 1
)

var ACKMessage = []byte("ACK")

type Audio struct {
	OpusPCM   []byte    `json:"pcm"`
	Timestamp time.Time `json:"time"`
}

type AudioChunk struct {
	BasePCM     []int16
	Contributor uuid.UUID
	Timestamp   time.Time
}

type AudioBuffer struct {
	Mu     sync.Mutex
	Buffer []*AudioChunk
}

type Room struct {
	AudioBuf *AudioBuffer
	Clients  []uuid.UUID
	RoomID   uuid.UUID
	Mu       sync.Mutex
}
