package utils

import (
	"bytes"

	"github.com/klauspost/reedsolomon"
)

type ForwardEC struct {
  encoder reedsolomon.Encoder
  dataShards int
  parityBits int
}

// Create an Encoder Object 
func NewEncoder(datashards,paritybits int) (*ForwardEC,error) {
  enc, err := reedsolomon.New(datashards,paritybits);if err != nil { return nil,err }
  return &ForwardEC{
    encoder: enc,
    dataShards: datashards,
    parityBits: paritybits,
  },nil
}

func (f *ForwardEC) EncodeData(data []byte) ([]byte,error) {
  shards, err := f.encoder.Split(data); if err != nil { return nil,err }
  err = f.encoder.Encode(shards); if err != nil { return nil,err }
  var buf bytes.Buffer
  outSize := len(data)
  err = f.encoder.Join(&buf,shards,outSize); if err != nil { return nil,err }
  return buf.Bytes(),nil
}

// The bool output is to see if there was any error in the in the encoded data
func (f *ForwardEC) DecodeData(encoded []byte) ([]byte,bool,error) {
  shards,err := f.encoder.Split(encoded); if err != nil { return nil,false,err }
  ok,err := f.encoder.Verify(shards)
  if err != nil { return nil,false,err }
  if !ok {
    err = f.encoder.Reconstruct(shards); if err != nil { return nil,false,err }
  }
  var buf bytes.Buffer
  outSize := int((len(shards)*len(shards[0])) - (f.parityBits * len(shards[0])))
  err = f.encoder.Join(&buf,shards,outSize); if err != nil { return nil,false,err }
  return buf.Bytes(),ok,nil
}
