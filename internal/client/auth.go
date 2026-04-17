package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/toucan/toucan-calls/internal/utils/encrypt"
	"github.com/toucan/toucan-calls/internal/utils/values"
	"golang.org/x/term"
)

func (c *Client) authenticate(username, password string) error {
	msg := values.AuthMessage{
		Username: username,
		Password: password,
	}

	raw, _ := json.Marshal(msg)
	enc, _ := encrypt.EncryptAES(raw, c.AESKey)

	_, err := c.Conn.Write(enc)
	if err != nil {
		return err
	}

	resp := make([]byte, 32)
	n, err := c.Conn.Read(resp)
	if err != nil {
		return err
	}

	if string(resp[:n]) != "AUTH_OK" {
		return fmt.Errorf("auth failed")
	}

	c.Log.Info("authenticated")
	return nil
}

func promptCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	fmt.Print("password: ")
	passBytes, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	password := strings.TrimSpace(string(passBytes))
	return username, password
}
