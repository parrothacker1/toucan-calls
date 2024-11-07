package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/sirupsen/logrus"
)

func EncryptAES(data []byte,key []byte) ([]byte,error) {
  block, err := aes.NewCipher(key); if err != nil { logrus.Errorf("Error in creating AES Cipher: %v\n",err);return nil,err }
  gcm, err := cipher.NewGCM(block); if err != nil { logrus.Errorf("Error in creating GCM Object: %v\n",err);return nil,err }
  nonce := make([]byte,gcm.NonceSize())
  _,err = rand.Read(nonce); if err != nil { logrus.Errorf("Error in creating Nonce: %v\n",err);return nil,err }
  return gcm.Seal(nonce,nonce,data,nil), nil
}

func DecryptAES(ciphertext []byte,key []byte) ([]byte,error) {
  block, err := aes.NewCipher(key); if err != nil { logrus.Errorf("Error in creating AES Cipher: %v\n",err);return nil,err }
  gcm, err := cipher.NewGCM(block); if err != nil { logrus.Errorf("Error in creating GCM Object: %v\n",err);return nil,err }
  if len(ciphertext) < gcm.NonceSize() { logrus.Errorf("Ciphertext is too short");return nil,err }
  nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
  data, err := gcm.Open(nil, nonce, ciphertext, nil); if err != nil { logrus.Errorf("Error in opening ciphertext: %v\n",err);return nil,err}
  return data,nil
}
