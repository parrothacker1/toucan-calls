package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/ishidawataru/sctp"
	"github.com/toucan/toucan-calls/utils"
)

func main() {
	host := os.Getenv("SERVER_HOST")
	port := os.Getenv("SERVER_PORT")
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "3000"
	}

	addr, err := sctp.ResolveSCTPAddr("sctp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		log.Fatalf("Failed to resolve server address: %v\n", err)
	}

	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v\n", err)
	}
	defer conn.Close()
	fmt.Println("Connected to server", conn.RemoteAddr().String())

	var wg sync.WaitGroup
	wg.Add(2)

	// Step 1: Receive ECC public key from server
	publicKeyBytes := make([]byte, 64) // Assuming 256-bit ECC (32 bytes X, 32 bytes Y)
	_, err = conn.Read(publicKeyBytes)
	if err != nil {
		log.Fatalf("Error reading ECC public key from server: %v\n", err)
	}

	serverPublicKey, err := utils.BytesToPubKey(publicKeyBytes)
	if err != nil {
		log.Fatalf("Error converting ECC public key bytes: %v\n", err)
	}
	fmt.Println("Received ECC public key from server.")

	// Step 2: Generate AES key
	aesKey := make([]byte, 32) // AES-256, so 32 bytes key
	_, err = rand.Read(aesKey)
	if err != nil {
		log.Fatalf("Error generating AES key: %v\n", err)
	}
	fmt.Println("Generated AES key.")

	// Step 3: Encrypt AES key with server's ECC public key
	encryptedAESKey, err := utils.EncryptECC(aesKey, serverPublicKey)
	if err != nil {
		log.Fatalf("Error encrypting AES key with ECC: %v\n", err)
	}

	// Step 4: Send encrypted AES key to server
	_, err = conn.Write(encryptedAESKey)
	if err != nil {
		log.Fatalf("Error sending encrypted AES key to server: %v\n", err)
	}
	fmt.Println("Sent encrypted AES key to server.")

	// Step 5: Wait for ACK from server
	ackMessage := make([]byte, 3) // expecting "ACK"
	_, err = conn.Read(ackMessage)
	if err != nil {
		log.Fatalf("Error reading ACK from server: %v\n", err)
	}
	if string(ackMessage) == "ACK" {
		fmt.Println("Received ACK from server.")
	} else {
		log.Fatalf("Did not receive proper ACK from server.")
	}

	// Step 6: Establish AES object with the key (can use utils.NewAES)
	aesObj, err := utils.NewAES(aesKey)
	if err != nil {
		log.Fatalf("Unable to generate new AES object: %v\n", err)
	}

	// Step 7: Full-duplex communication (this part can be customized)
	duplex := utils.NewDuplex(conn)

	go duplex.ReadLoop() // Reading data from server
	message := []byte("Thanks from client")
	encodedData, err := aesObj.Encrypt(message)
	if err != nil {
		log.Fatalf("Error encrypting message: %v\n", err)
	}
	go duplex.WriteLoop(encodedData) // Sending data to server

	wg.Wait()
}

