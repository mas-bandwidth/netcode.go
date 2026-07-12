/*
netcode example server

Runs a netcode server on 127.0.0.1:40000 and [::1]:40000 (or the addresses
passed as arguments) and exchanges payload packets with connected clients
until interrupted.
*/
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"time"

	netcode "github.com/mas-bandwidth/netcode.go"
)

const protocolID = 0x1122334455667788

var privateKey = [netcode.KeyBytes]byte{
	0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
	0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
	0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
	0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
}

func main() {
	netcode.SetLogLevel(netcode.LogLevelInfo)

	currentTime := 0.0
	deltaTime := 1.0 / 60.0

	fmt.Printf("[server]\n")

	serverAddressIPv4 := "127.0.0.1:40000"
	serverAddressIPv6 := "[::1]:40000"
	if len(os.Args) == 2 {
		serverAddressIPv4 = os.Args[1]
		serverAddressIPv6 = ""
	} else if len(os.Args) == 3 {
		serverAddressIPv4 = os.Args[1]
		serverAddressIPv6 = os.Args[2]
	}

	serverConfig := &netcode.ServerConfig{
		ProtocolID: protocolID,
		PrivateKey: privateKey,
	}

	server, err := netcode.NewServerDual(serverAddressIPv4, serverAddressIPv6, serverConfig, currentTime)
	if err != nil {
		fmt.Printf("error: failed to create server (%v)\n", err)
		os.Exit(1)
	}

	server.Start(netcode.MaxClients)

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

		server.Update(currentTime)

		if server.ClientConnected(0) {
			server.SendPacket(0, packetData)
		}

		for clientIndex := 0; clientIndex < netcode.MaxClients; clientIndex++ {
			for {
				packet, _ := server.ReceivePacket(clientIndex)
				if packet == nil {
					break
				}
				if len(packet) != netcode.MaxPacketSize || !bytes.Equal(packet, packetData) {
					panic("received packet data does not match")
				}
			}
		}

		time.Sleep(time.Duration(deltaTime * float64(time.Second)))

		currentTime += deltaTime
	}

	if quit {
		fmt.Printf("\nshutting down\n")
	}

	server.Close()
}
