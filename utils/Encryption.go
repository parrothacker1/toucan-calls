package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

type ECC struct {
  PrivateKey *ecdsa.PrivateKey
  PublicKey *ecdsa.PublicKey 
}

func GenerateECCKeys() (*ECC,error) {
  privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    return nil,err
  }
  return &ECC {
    PrivateKey: privKey, 
    PublicKey: &privKey.PublicKey,
  }, nil
}

func (e *ECC) DecryptECC(data []byte) ([]byte,error){
  return data,nil
}

type AES struct {
  key []byte
}

func NewAES(key []byte) (*AES,error){
  return &AES { key: key },nil
}

func (a *AES) Encrypt(data []byte) ([]byte,error) {
  return data,nil
}

func (a *AES) Decrypt(data []byte) ([]byte,error) {
  return data,nil
}
