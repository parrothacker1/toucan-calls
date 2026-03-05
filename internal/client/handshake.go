package client

import (
	"crypto/rand"
	"fmt"

	ecies "github.com/ecies/go/v2"
	"github.com/toucan/toucan-calls/internal/utils/values"
)

func (c *Client) handshake() error {
	c.Log.Info("starting ecc handshake")

	c.AESKey = make([]byte, 32)
	if _, err := rand.Read(c.AESKey); err != nil {
		return fmt.Errorf("aes key generation failed: %w", err)
	}
	c.Log.Debug("aes session key generated")

	pubKeyBuf := make([]byte, 256)
	n, err := c.Conn.Read(pubKeyBuf)
	if err != nil {
		return fmt.Errorf("failed to read server public key: %w", err)
	}
	pubKeyHex := string(pubKeyBuf[:n])
	pubKey, err := ecies.NewPublicKeyFromHex(pubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}
	c.PublicKey = pubKey
	c.Log.Debug("server public key received")

	encAES, err := ecies.Encrypt(pubKey, c.AESKey)
	if err != nil {
		return fmt.Errorf("aes encryption failed: %w", err)
	}
	if _, err := c.Conn.Write(encAES); err != nil {
		return fmt.Errorf("failed to send encrypted aes key: %w", err)
	}
	c.Log.Debug("encrypted aes key sent")

	ack := make([]byte, 64)
	n, err = c.Conn.Read(ack)
	if err != nil {
		return fmt.Errorf("failed to receive handshake ack: %w", err)
	}
	if string(ack[:n]) != string(values.ACKMessage) {
		return fmt.Errorf("handshake failed: invalid ack")
	}
	c.Log.WithField("ack_bytes", n).Debug("handshake acknowledgement received")

	c.Log.Info("secure session established")
	return nil
}
