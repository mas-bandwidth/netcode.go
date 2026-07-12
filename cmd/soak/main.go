/*
netcode soak test

Randomly creates and destroys clients and servers, connects and disconnects
clients, and exchanges payload packets between them, forever (or for the
number of iterations passed as the first argument). Run it to shake out
lifetime and state machine bugs.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strconv"

	netcode "github.com/mas-bandwidth/netcode.go"
)

const (
	maxServers          = 2
	maxClients          = 64
	serverBasePort      = 20000
	connectTokenExpiry  = 45
	connectTokenTimeout = 5
	protocolID          = 0x1122334455667788
)

var servers [maxServers]*netcode.Server
var clients [maxClients]*netcode.Client
var packetData [netcode.MaxPacketSize]byte
var privateKey [netcode.KeyBytes]byte

func randomInt(a, b int) int {
	return a + rand.Intn(b-a+1)
}

func soakInitialize() {
	fmt.Printf("initializing\n")

	netcode.SetLogLevel(netcode.LogLevelInfo)

	netcode.RandomBytes(privateKey[:])

	for i := range packetData {
		packetData[i] = byte(i)
	}
}

func soakShutdown() {
	fmt.Printf("shutdown\n")

	for i := 0; i < maxServers; i++ {
		if servers[i] != nil {
			servers[i].Close()
			servers[i] = nil
		}
	}

	for i := 0; i < maxClients; i++ {
		if clients[i] != nil {
			clients[i].Close()
			clients[i] = nil
		}
	}
}

func soakIteration(time float64) {
	serverConfig := &netcode.ServerConfig{
		ProtocolID: protocolID,
		PrivateKey: privateKey,
	}

	for i := 0; i < maxServers; i++ {
		if servers[i] == nil && randomInt(0, 10) == 0 {
			serverAddress := fmt.Sprintf("127.0.0.1:%d", serverBasePort+i)
			servers[i], _ = netcode.NewServer(serverAddress, serverConfig, time)
			fmt.Printf("created server %s\n", serverAddress)
		}

		if servers[i] != nil && servers[i].NumConnectedClients() == servers[i].MaxClients() && randomInt(0, 10000) == 0 {
			fmt.Printf("destroy server %d\n", i)
			servers[i].Close()
			servers[i] = nil
		}
	}

	for i := 0; i < maxClients; i++ {
		if clients[i] == nil && randomInt(0, 10) == 0 {
			var err error
			clients[i], err = netcode.NewClient("0.0.0.0", nil, time)
			if err != nil {
				fmt.Printf("failed to create client (%v)\n", err)
				os.Exit(1)
			}
			fmt.Printf("created client %d\n", i)
		}

		if clients[i] != nil && randomInt(0, 1000) == 0 {
			fmt.Printf("destroy client %d\n", i)
			clients[i].Close()
			clients[i] = nil
		}
	}

	for i := 0; i < maxServers; i++ {
		if servers[i] == nil {
			continue
		}

		if randomInt(0, 10) == 0 && !servers[i].Running() {
			servers[i].Start(randomInt(1, netcode.MaxClients))
		}

		if randomInt(0, 1000) == 0 && servers[i].NumConnectedClients() == servers[i].MaxClients() && servers[i].Running() {
			servers[i].Stop()
		}

		if servers[i].Running() {
			serverMaxClients := servers[i].MaxClients()

			for clientIndex := 0; clientIndex < serverMaxClients; clientIndex++ {
				if servers[i].ClientConnected(clientIndex) {
					servers[i].SendPacket(clientIndex, packetData[:randomInt(1, netcode.MaxPacketSize)])
				}
			}

			for clientIndex := 0; clientIndex < serverMaxClients; clientIndex++ {
				if servers[i].ClientConnected(clientIndex) {
					for {
						packet, _ := servers[i].ReceivePacket(clientIndex)
						if packet == nil {
							break
						}
						if !bytes.Equal(packet, packetData[:len(packet)]) {
							panic("received packet data does not match")
						}
					}
				}
			}
		}

		servers[i].Update(time)
	}

	for i := 0; i < maxClients; i++ {
		if clients[i] == nil {
			continue
		}

		if randomInt(0, 10) == 0 && clients[i].State() <= netcode.ClientStateDisconnected {
			var clientIDBytes [8]byte
			netcode.RandomBytes(clientIDBytes[:])
			clientID := binary.LittleEndian.Uint64(clientIDBytes[:])

			userData := make([]byte, netcode.UserDataBytes)
			netcode.RandomBytes(userData)

			var serverAddresses []string
			for j := 0; j < maxServers; j++ {
				if len(serverAddresses) == netcode.MaxServersPerConnect {
					break
				}
				if servers[j] != nil && servers[j].Running() {
					serverAddresses = append(serverAddresses, fmt.Sprintf("127.0.0.1:%d", serverBasePort+j))
				}
			}

			if len(serverAddresses) > 0 {
				connectToken, err := netcode.GenerateConnectToken(serverAddresses, serverAddresses,
					connectTokenExpiry, connectTokenTimeout, clientID, protocolID, privateKey[:], userData)
				if err == nil {
					clients[i].Connect(connectToken)
				}
			}
		}

		if randomInt(0, 100) == 0 && clients[i].State() == netcode.ClientStateConnected {
			clients[i].Disconnect()
		}

		if clients[i].State() == netcode.ClientStateConnected {
			clients[i].SendPacket(packetData[:randomInt(1, netcode.MaxPacketSize)])

			for {
				packet, _ := clients[i].ReceivePacket()
				if packet == nil {
					break
				}
				if !bytes.Equal(packet, packetData[:len(packet)]) {
					panic("received packet data does not match")
				}
			}
		}

		clients[i].Update(time)
	}
}

func main() {
	numIterations := -1

	if len(os.Args) == 2 {
		numIterations, _ = strconv.Atoi(os.Args[1])
	}

	fmt.Printf("[soak]\nnum_iterations = %d\n", numIterations)

	soakInitialize()

	fmt.Printf("starting\n")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	quit := func() bool {
		select {
		case <-interrupt:
			return true
		default:
			return false
		}
	}

	time := 0.0
	deltaTime := 0.1

	if numIterations > 0 {
		for i := 0; i < numIterations; i++ {
			if quit() {
				break
			}

			soakIteration(time)

			time += deltaTime
		}
	} else {
		for !quit() {
			soakIteration(time)

			time += deltaTime
		}
	}

	soakShutdown()
}
