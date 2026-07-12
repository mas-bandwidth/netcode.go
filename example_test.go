package netcode_test

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	netcode "github.com/mas-bandwidth/netcode.go"
)

// A dedicated server: create it with the private key shared with the web
// backend, start it with the number of client slots, then update it every
// frame, exchanging payload packets with connected clients.
func ExampleNewServer() {
	var privateKey [netcode.KeyBytes]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		log.Fatal(err)
	}

	config := &netcode.ServerConfig{
		ProtocolID: 0x1122334455667788,
		PrivateKey: privateKey,
	}

	server, err := netcode.NewServer("127.0.0.1:40000", config, 0.0)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}
	defer server.Close()

	server.Start(16)

	start := time.Now()
	deltaTime := time.Second / 60

	for i := 0; i < 10; i++ { // your game loop
		server.Update(time.Since(start).Seconds())

		for clientIndex := 0; clientIndex < server.MaxClients(); clientIndex++ {
			for {
				packet, sequence := server.ReceivePacket(clientIndex)
				if packet == nil {
					break
				}
				_ = sequence // process the payload packet from this client...
			}
		}

		time.Sleep(deltaTime)
	}
}

// A client: obtain a connect token from your web backend over HTTPS, then
// connect and update every frame until connected (or an error state).
func ExampleNewClient() {
	client, err := netcode.NewClient("0.0.0.0:0", nil, 0.0)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	connectToken := requestConnectTokenFromWebBackend()

	client.Connect(connectToken)

	start := time.Now()
	deltaTime := time.Second / 60

	for i := 0; i < 10; i++ { // your game loop
		client.Update(time.Since(start).Seconds())

		if client.State() == netcode.ClientStateConnected {
			client.SendPacket([]byte("hello server"))
		}

		if client.State() <= netcode.ClientStateDisconnected {
			fmt.Printf("client failed to connect: %s\n", netcode.ClientStateName(client.State()))
			break
		}

		time.Sleep(deltaTime)
	}
}

// The web backend generates a connect token for an authenticated client and
// returns it over HTTPS. Only the backend and the dedicated servers know the
// private key.
func ExampleGenerateConnectToken() {
	var privateKey [netcode.KeyBytes]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		log.Fatal(err)
	}

	var clientIDBytes [8]byte
	if _, err := rand.Read(clientIDBytes[:]); err != nil {
		log.Fatal(err)
	}
	clientID := binary.LittleEndian.Uint64(clientIDBytes[:])

	serverAddresses := []string{"127.0.0.1:40000"}

	const (
		expireSeconds  = 30 // how long the token stays valid
		timeoutSeconds = 5  // how long before an idle connection times out
		protocolID     = 0x1122334455667788
	)

	connectToken, err := netcode.GenerateConnectToken(
		serverAddresses, // public addresses the client connects to
		serverAddresses, // internal addresses the servers see themselves as
		expireSeconds, timeoutSeconds, clientID, protocolID, privateKey[:],
		nil, // optional user data, up to netcode.UserDataBytes
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("connect token is %d bytes\n", len(connectToken))
	// Output: connect token is 2048 bytes
}

// requestConnectTokenFromWebBackend stands in for hitting a REST API on your
// web backend that authenticates the client and returns a connect token.
func requestConnectTokenFromWebBackend() []byte {
	var privateKey [netcode.KeyBytes]byte
	token, err := netcode.GenerateConnectToken(
		[]string{"127.0.0.1:40000"}, []string{"127.0.0.1:40000"},
		30, 5, 1, 0x1122334455667788, privateKey[:], nil)
	if err != nil {
		log.Fatal(err)
	}
	return token
}
