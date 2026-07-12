/*
netcode example client

Connects to a netcode server at 127.0.0.1:40000 (or the address passed as
the first argument) and exchanges payload packets with it until interrupted.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"time"

	netcode "github.com/mas-bandwidth/netcode.go"
)

const (
	connectTokenExpiry  = 30
	connectTokenTimeout = 5
	protocolID          = 0x1122334455667788
)

var privateKey = []byte{
	0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
	0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
	0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
	0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
}

func main() {
	netcode.SetLogLevel(netcode.LogLevelInfo)

	currentTime := 0.0
	deltaTime := 1.0 / 60.0

	fmt.Printf("[client]\n")

	client, err := netcode.NewClientDual("0.0.0.0", "::", nil, currentTime)
	if err != nil {
		fmt.Printf("error: failed to create client (%v)\n", err)
		os.Exit(1)
	}

	serverAddress := "127.0.0.1:40000"
	if len(os.Args) == 2 {
		serverAddress = os.Args[1]
	}

	var clientIDBytes [8]byte
	netcode.RandomBytes(clientIDBytes[:])
	clientID := binary.LittleEndian.Uint64(clientIDBytes[:])
	fmt.Printf("client id is %.16x\n", clientID)

	userData := make([]byte, netcode.UserDataBytes)
	netcode.RandomBytes(userData)

	connectToken, err := netcode.GenerateConnectToken([]string{serverAddress}, []string{serverAddress},
		connectTokenExpiry, connectTokenTimeout, clientID, protocolID, privateKey, userData)
	if err != nil {
		fmt.Printf("error: failed to generate connect token (%v)\n", err)
		os.Exit(1)
	}

	client.Connect(connectToken)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	packetData := make([]byte, netcode.MaxPacketSize)
	for i := range packetData {
		packetData[i] = byte(i)
	}

	quit := false

	for !quit {
		select {
		case <-interrupt:
			quit = true
			continue
		default:
		}

		client.Update(currentTime)

		if client.State() == netcode.ClientStateConnected {
			client.SendPacket(packetData)
		}

		for {
			packet, _ := client.ReceivePacket()
			if packet == nil {
				break
			}
			if len(packet) != netcode.MaxPacketSize || !bytes.Equal(packet, packetData) {
				panic("received packet data does not match")
			}
		}

		if client.State() <= netcode.ClientStateDisconnected {
			break
		}

		time.Sleep(time.Duration(deltaTime * float64(time.Second)))

		currentTime += deltaTime
	}

	if quit {
		fmt.Printf("\nshutting down\n")
	}

	client.Close()
}
