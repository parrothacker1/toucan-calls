package codec

import (
	"github.com/hraban/opus"
	"github.com/toucan/toucan-calls/internal/utils/encoder"
)

var (
	FECEncoder  *encoder.FEC
	OpusEncoder *opus.Encoder
	OpusDecoder *opus.Decoder
)

func init() {
	var err error
	FECEncoder, err = encoder.NewEncoder(6, 3)
	if err != nil {
		panic(err)
	}
	OpusEncoder, err = opus.NewEncoder(48000, 1, opus.AppVoIP)
	if err != nil {
		panic(err)
	}
	OpusDecoder, err = opus.NewDecoder(48000, 1)
	if err != nil {
		panic(err)
	}
}
