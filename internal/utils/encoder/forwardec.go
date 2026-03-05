package encoder

import (
	"bytes"
	"encoding/binary"

	"github.com/klauspost/reedsolomon"
)

type FEC struct {
	encoder    reedsolomon.Encoder
	dataShards int
	parityBits int
}

// Create an Encoder Object
func NewEncoder(datashards, paritybits int) (*FEC, error) {
	enc, err := reedsolomon.New(datashards, paritybits)
	if err != nil {
		return nil, err
	}
	return &FEC{
		encoder:    enc,
		dataShards: datashards,
		parityBits: paritybits,
	}, nil
}

func (f *FEC) EncodeData(data []byte) ([]byte, error) {
	shards, err := f.encoder.Split(data)
	if err != nil {
		return nil, err
	}
	if err := f.encoder.Encode(shards); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(data)))
	if err := f.encoder.Join(&buf, shards, len(data)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// The bool output is to see if there was any error in the in the encoded data
func (f *FEC) DecodeData(encoded []byte) ([]byte, bool, error) {
	buf := bytes.NewReader(encoded)
	var originalSize uint32
	if err := binary.Read(buf, binary.BigEndian, &originalSize); err != nil {
		return nil, false, err
	}
	payload := encoded[4:]
	shards, err := f.encoder.Split(payload)
	if err != nil {
		return nil, false, err
	}
	ok, err := f.encoder.Verify(shards)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		if err := f.encoder.Reconstruct(shards); err != nil {
			return nil, false, err
		}
	}
	var out bytes.Buffer
	if err := f.encoder.Join(&out, shards, int(originalSize)); err != nil {
		return nil, false, err
	}
	return out.Bytes(), ok, nil
}
