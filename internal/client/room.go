package client

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/toucan/toucan-calls/internal/utils/encrypt"
)

func (c *Client) joinRoom() error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("1.Create a room\n2.Join a room\nOption -> ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)
	var roomID string
	if choice == "1" {
		roomID = uuid.New().String()
		fmt.Println("Room ID:", roomID)
	} else {
		fmt.Print("Enter Room ID: ")
		roomID, _ = reader.ReadString('\n')
		roomID = strings.TrimSpace(roomID)
	}
	return c.joinRoomByID(roomID)
}

// joinRoomByID sends the room ID to the server (used by both CLI and Web UI)
func (c *Client) joinRoomByID(roomID string) error {
	roomEnc, err := encrypt.EncryptAES([]byte(roomID), c.AESKey)
	if err != nil {
		return fmt.Errorf("room encryption failed: %w", err)
	}
	_, err = c.Conn.Write(roomEnc)
	return err
}
