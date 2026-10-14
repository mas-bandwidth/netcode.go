package netcode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func randomUint64() uint64 {
	var b [8]byte
	RandomBytes(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

func randomUserData() []byte {
	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)
	return userData
}

// newLossySimulator returns a network simulator with the adverse conditions
// used by the client/server tests in the C implementation.
func newLossySimulator() *NetworkSimulator {
	simulator := NewNetworkSimulator()
	simulator.LatencyMilliseconds = 250
	simulator.JitterMilliseconds = 250
	simulator.PacketLossPercent = 5
	simulator.DuplicatePacketPercent = 10
	return simulator
}

func generateTestConnectToken(t *testing.T, serverAddress string, expireSeconds int, timeoutSeconds int, clientID uint64) []byte {
	t.Helper()
	connectToken, err := GenerateConnectToken([]string{serverAddress}, []string{serverAddress},
		expireSeconds, timeoutSeconds, clientID, testProtocolID, testPrivateKey[:], randomUserData())
	check(t, err == nil)
	return connectToken
}

// pumpUntilConnected runs the standard connect loop: update the simulator,
// client and server until the client either connects or fails.
func pumpUntilConnected(simulator *NetworkSimulator, client *Client, server *Server, currentTime *float64, deltaTime float64) {
	for {
		simulator.Update(*currentTime)

		client.Update(*currentTime)

		server.Update(*currentTime)

		if client.State() <= ClientStateDisconnected {
			break
		}

		if client.State() == ClientStateConnected {
			break
		}

		*currentTime += deltaTime
	}
}

func TestClientServerConnect(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	serverNumPacketsReceived := 0
	clientNumPacketsReceived := 0

	packetData := make([]byte, MaxPacketSize)
	for i := range packetData {
		packetData[i] = uint8(i)
	}

	for {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		client.SendPacket(packetData)

		server.SendPacket(0, packetData)

		for {
			packet, _ := client.ReceivePacket()
			if packet == nil {
				break
			}
			check(t, len(packet) == MaxPacketSize)
			check(t, bytes.Equal(packet, packetData))
			clientNumPacketsReceived++
		}

		for {
			packet, _ := server.ReceivePacket(0)
			if packet == nil {
				break
			}
			check(t, len(packet) == MaxPacketSize)
			check(t, bytes.Equal(packet, packetData))
			serverNumPacketsReceived++
		}

		if clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10 {
			if server.ClientConnected(0) {
				server.DisconnectClient(0)
			}
		}

		if client.State() <= ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10)
}

func clientServerSocketConnectTo(t *testing.T, clientAddress, clientAddress2, serverAddress, serverAddress2, connectAddress string) {
	t.Helper()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	client, err := NewClientDual(clientAddress, clientAddress2, nil, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID: testProtocolID,
		PrivateKey: testPrivateKey,
	}

	server, err := NewServerDual(serverAddress, serverAddress2, serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, connectAddress, testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	for {
		client.Update(currentTime)

		server.Update(currentTime)

		if client.State() <= ClientStateDisconnected {
			break
		}

		if client.State() == ClientStateConnected {
			break
		}

		// this test runs over real sockets while advancing virtual time, so it must yield
		// real time each iteration or the virtual timeouts can expire before the OS delivers
		// a single loopback packet

		time.Sleep(10 * time.Millisecond)

		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnected)
	check(t, server.NumConnectedClients() == 1)
}

func clientServerSocketConnect(t *testing.T, clientAddress, clientAddress2, serverAddress, serverAddress2 string) {
	t.Helper()
	clientServerSocketConnectTo(t, clientAddress, clientAddress2, serverAddress, serverAddress2, serverAddress)
}

func TestClientServerIPv4SocketConnect(t *testing.T) {
	clientServerSocketConnect(t, "0.0.0.0:50000", "", "127.0.0.1:40000", "")
	clientServerSocketConnect(t, "0.0.0.0:50000", "", "127.0.0.1:40000", "[::1]:40000")
	clientServerSocketConnect(t, "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "")
	clientServerSocketConnect(t, "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000")
}

func TestClientServerIPv6SocketConnect(t *testing.T) {
	clientServerSocketConnect(t, "[::]:50000", "", "[::1]:40000", "")
	clientServerSocketConnect(t, "[::]:50000", "", "[::1]:40000", "127.0.0.1:40000")
	clientServerSocketConnect(t, "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "")
	clientServerSocketConnect(t, "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000")
}

func TestClientServerDualSocketConnect(t *testing.T) {
	// dual stack client connects to dual stack server over ipv4

	clientServerSocketConnect(t, "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000")

	// dual stack client connects to dual stack server over ipv6

	clientServerSocketConnect(t, "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000")

	// dual stack client connects to the second address of a dual stack server (ipv6, then ipv4)

	clientServerSocketConnectTo(t, "0.0.0.0:50000", "[::]:50000", "127.0.0.1:40000", "[::1]:40000", "[::1]:40000")

	clientServerSocketConnectTo(t, "0.0.0.0:50000", "[::]:50000", "[::1]:40000", "127.0.0.1:40000", "127.0.0.1:40000")
}

func TestClientServerKeepAlive(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	// connect client to server

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// pump the client and server long enough that they would timeout without keep alive packets

	numIterations := int(1.25*testTimeoutSeconds/deltaTime) + 1

	for i := 0; i < numIterations; i++ {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		if client.State() <= ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)
}

func TestClientServerMultipleClients(t *testing.T) {
	maxClients := []int{2, 32, 5}

	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	for i := 0; i < len(maxClients); i++ {
		// start the server with max # of clients for this iteration

		server.Start(maxClients[i])

		// create # of client objects for this iteration and connect to server

		clients := make([]*Client, maxClients[i])

		for j := 0; j < maxClients[i]; j++ {
			clientConfig := &ClientConfig{NetworkSimulator: simulator}

			clients[j], err = NewClient(fmt.Sprintf("[::]:%d", 50000+j), clientConfig, currentTime)
			check(t, err == nil)

			connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

			clients[j].Connect(connectToken)
		}

		// make sure all clients can connect

		for {
			simulator.Update(currentTime)

			for j := 0; j < maxClients[i]; j++ {
				clients[j].Update(currentTime)
			}

			server.Update(currentTime)

			numConnectedClients := 0

			for j := 0; j < maxClients[i]; j++ {
				if clients[j].State() <= ClientStateDisconnected {
					break
				}

				if clients[j].State() == ClientStateConnected {
					numConnectedClients++
				}
			}

			if numConnectedClients == maxClients[i] {
				break
			}

			currentTime += deltaTime
		}

		check(t, server.NumConnectedClients() == maxClients[i])

		for j := 0; j < maxClients[i]; j++ {
			check(t, clients[j].State() == ClientStateConnected)
			check(t, server.ClientConnected(j))
		}

		// make sure all clients can exchange packets with the server

		serverNumPacketsReceived := make([]int, maxClients[i])
		clientNumPacketsReceived := make([]int, maxClients[i])

		packetData := make([]byte, MaxPacketSize)
		for j := range packetData {
			packetData[j] = uint8(j)
		}

		for {
			simulator.Update(currentTime)

			for j := 0; j < maxClients[i]; j++ {
				clients[j].Update(currentTime)
			}

			server.Update(currentTime)

			for j := 0; j < maxClients[i]; j++ {
				clients[j].SendPacket(packetData)
			}

			for j := 0; j < maxClients[i]; j++ {
				server.SendPacket(j, packetData)
			}

			for j := 0; j < maxClients[i]; j++ {
				for {
					packet, _ := clients[j].ReceivePacket()
					if packet == nil {
						break
					}
					check(t, len(packet) == MaxPacketSize)
					check(t, bytes.Equal(packet, packetData))
					clientNumPacketsReceived[j]++
				}
			}

			for j := 0; j < maxClients[i]; j++ {
				for {
					packet, _ := server.ReceivePacket(j)
					if packet == nil {
						break
					}
					check(t, len(packet) == MaxPacketSize)
					check(t, bytes.Equal(packet, packetData))
					serverNumPacketsReceived[j]++
				}
			}

			numClientsReady := 0

			for j := 0; j < maxClients[i]; j++ {
				if clientNumPacketsReceived[j] >= 1 && serverNumPacketsReceived[j] >= 1 {
					numClientsReady++
				}
			}

			if numClientsReady == maxClients[i] {
				break
			}

			for j := 0; j < maxClients[i]; j++ {
				if clients[j].State() <= ClientStateDisconnected {
					break
				}
			}

			currentTime += deltaTime
		}

		numClientsReady := 0

		for j := 0; j < maxClients[i]; j++ {
			if clientNumPacketsReceived[j] >= 1 && serverNumPacketsReceived[j] >= 1 {
				numClientsReady++
			}
		}

		check(t, numClientsReady == maxClients[i])

		simulator.Reset()

		for j := 0; j < maxClients[i]; j++ {
			clients[j].Close()
		}

		server.Stop()
	}
}

func TestClientServerMultipleServers(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	// the first two server addresses are unreachable. the client works through them
	// and connects to the third.

	serverAddresses := []string{"10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000"}

	connectToken, err := GenerateConnectToken(serverAddresses, serverAddresses,
		testConnectTokenExpiry, testTimeoutSeconds, randomUint64(), testProtocolID, testPrivateKey[:], randomUserData())
	check(t, err == nil)

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	serverNumPacketsReceived := 0
	clientNumPacketsReceived := 0

	packetData := make([]byte, MaxPacketSize)
	for i := range packetData {
		packetData[i] = uint8(i)
	}

	for {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		client.SendPacket(packetData)

		server.SendPacket(0, packetData)

		for {
			packet, _ := client.ReceivePacket()
			if packet == nil {
				break
			}
			check(t, len(packet) == MaxPacketSize)
			check(t, bytes.Equal(packet, packetData))
			clientNumPacketsReceived++
		}

		for {
			packet, _ := server.ReceivePacket(0)
			if packet == nil {
				break
			}
			check(t, len(packet) == MaxPacketSize)
			check(t, bytes.Equal(packet, packetData))
			serverNumPacketsReceived++
		}

		if clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10 {
			if server.ClientConnected(0) {
				server.DisconnectClient(0)
			}
		}

		if client.State() <= ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10)
}

func TestClientErrorConnectTokenExpired(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	connectToken := generateTestConnectToken(t, "[::1]:40000", 0, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	client.Update(currentTime)

	check(t, client.State() == ClientStateConnectTokenExpired)
}

func TestClientErrorInvalidConnectToken(t *testing.T) {
	simulator := newLossySimulator()

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, 0.0)
	check(t, err == nil)
	defer client.Close()

	connectToken := make([]byte, ConnectTokenBytes)
	RandomBytes(connectToken)

	client.Connect(connectToken)

	check(t, client.State() == ClientStateInvalidConnectToken)
}

func TestClientErrorConnectionTimedOut(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	// connect a client to the server

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// now disable updating the server and verify that the client times out

	for {
		simulator.Update(currentTime)

		client.Update(currentTime)

		if client.State() <= ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnectionTimedOut)
}

func TestClientErrorConnectionResponseTimeout(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.flags = serverFlagIgnoreConnectionResponsePackets

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnectionResponseTimedOut)
}

func TestClientErrorConnectionRequestTimeout(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 60.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.flags = serverFlagIgnoreConnectionRequestPackets

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnectionRequestTimedOut)
}

func TestClientErrorConnectionDenied(t *testing.T) {
	simulator := newLossySimulator()

	// start a server and connect one client

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// now attempt to connect a second client. the connection should be denied.

	client2, err := NewClient("[::]:50001", clientConfig, currentTime)
	check(t, err == nil)
	defer client2.Close()

	connectToken2 := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client2.Connect(connectToken2)

	for {
		simulator.Update(currentTime)

		client.Update(currentTime)

		client2.Update(currentTime)

		server.Update(currentTime)

		if client.State() <= ClientStateDisconnected {
			break
		}

		if client2.State() <= ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnected)
	check(t, client2.State() == ClientStateConnectionDenied)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)
}

func TestClientSideDisconnect(t *testing.T) {
	simulator := NewNetworkSimulator()

	// start a server and connect one client

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

	client.Disconnect()

	for i := 0; i < 10; i++ {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		if !server.ClientConnected(0) {
			break
		}

		currentTime += deltaTime
	}

	check(t, !server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 0)
	check(t, server.ClientDisconnectReason(0) == DisconnectReasonClientDisconnect)
}

func TestServerSideDisconnect(t *testing.T) {
	simulator := NewNetworkSimulator()

	// start a server and connect one client

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// disconnect server side and verify that the client disconnects cleanly, rather than timing out.

	server.DisconnectClient(0)

	for i := 0; i < 10; i++ {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		if client.State() == ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateDisconnected)
	check(t, !server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 0)
	check(t, server.ClientDisconnectReason(0) == DisconnectReasonServerDisconnect)
}

func TestServerClientDisconnectReason(t *testing.T) {
	simulator := NewNetworkSimulator()

	// start a server and connect one client

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	// no disconnect has happened yet, so the client slot reason is none

	check(t, server.ClientDisconnectReason(0) == DisconnectReasonNone)

	clientID := randomUint64()

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, clientID)

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, server.ClientConnected(0))
	check(t, server.ClientDisconnectReason(0) == DisconnectReasonNone)

	// stop updating the client so it goes silent. the server should time it out
	// and record that as the disconnect reason, distinct from a clean disconnect

	for i := 0; i < 200; i++ {
		simulator.Update(currentTime)

		server.Update(currentTime)

		if !server.ClientConnected(0) {
			break
		}

		currentTime += deltaTime
	}

	check(t, !server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 0)
	check(t, server.ClientDisconnectReason(0) == DisconnectReasonTimedOut)

	// reconnect. a new client connecting to the slot clears the reason back to none

	client.Disconnect()

	// catch the client's internal clock up to the current time before reconnecting, since it
	// was deliberately not updated above. otherwise the first update after connect sees the
	// whole timeout leg as elapsed time and immediately times out the connection request.
	client.Update(currentTime)

	simulator.Reset()

	connectToken = generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, clientID)

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, server.ClientConnected(0))
	check(t, server.ClientDisconnectReason(0) == DisconnectReasonNone)
}

// scriptedReceive plays a fixed queue through the receive override and counts
// every call. A nil queue entry stands for a datagram to skip (the override
// result -1): a zero-length datagram or a receive error that the loop must not
// hand to the packet processor. The returned pointer counts the iterations so a
// test can assert how many datagrams one Update consumed.
func scriptedReceive(queue [][]byte) (func() ([]byte, Address, int), *int) {
	remaining := append([][]byte(nil), queue...)
	calls := 0
	return func() ([]byte, Address, int) {
		if len(remaining) == 0 {
			return nil, Address{}, 0
		}
		item := remaining[0]
		remaining = remaining[1:]
		calls++
		if item == nil {
			return nil, Address{}, -1
		}
		return item, Address{}, len(item)
	}, &calls
}

// TestReceiveDrainSkipsEmptyAndStopsAtCap pins the receive loop against the C
// reference. One Update consumes at most the per-update cap
// (serverMaxReceivePackets, or clientMaxReceivePackets on the client side), it
// counts every iteration including skipped zero-length datagrams, and a skip
// (-1) keeps draining instead of ending the loop. The transport is the override
// seam, so no socket is opened and no wall clock is read.
func TestReceiveDrainSkipsEmptyAndStopsAtCap(t *testing.T) {
	junk := []byte("junk")

	// the server consumes exactly the cap out of cap+10 junk datagrams

	saturated := make([][]byte, serverMaxReceivePackets+10)
	for i := range saturated {
		saturated[i] = junk
	}
	override, calls := scriptedReceive(saturated)
	server, err := NewServer("127.0.0.1:40000", &ServerConfig{
		ProtocolID:             testProtocolID,
		PrivateKey:             testPrivateKey,
		OverrideSendAndReceive: true,
		ReceivePacketOverride:  override,
	}, 0)
	check(t, err == nil)
	defer server.Close()
	server.Start(1)
	server.Update(1.0)
	check(t, *calls == serverMaxReceivePackets)

	// a skipped datagram between two junk datagrams is consumed whole: three
	// override calls, and the skip does not end the loop

	override, calls = scriptedReceive([][]byte{junk, nil, junk})
	server, err = NewServer("127.0.0.1:40001", &ServerConfig{
		ProtocolID:             testProtocolID,
		PrivateKey:             testPrivateKey,
		OverrideSendAndReceive: true,
		ReceivePacketOverride:  override,
	}, 0)
	check(t, err == nil)
	defer server.Close()
	server.Start(1)
	server.Update(1.0)
	check(t, *calls == 3)

	// the client obeys its own cap

	clientSaturated := make([][]byte, clientMaxReceivePackets+10)
	for i := range clientSaturated {
		clientSaturated[i] = junk
	}
	clientOverride, clientCalls := scriptedReceive(clientSaturated)
	client, err := NewClient("127.0.0.1:41000", &ClientConfig{
		OverrideSendAndReceive: true,
		ReceivePacketOverride:  clientOverride,
	}, 0)
	check(t, err == nil)
	defer client.Close()
	client.Update(1.0)
	check(t, *clientCalls == clientMaxReceivePackets)

	// the client drains a [junk, skip, junk] queue whole too

	clientOverride, clientCalls = scriptedReceive([][]byte{junk, nil, junk})
	client, err = NewClient("127.0.0.1:41001", &ClientConfig{
		OverrideSendAndReceive: true,
		ReceivePacketOverride:  clientOverride,
	}, 0)
	check(t, err == nil)
	defer client.Close()
	client.Update(1.0)
	check(t, *clientCalls == 3)
}

func TestClientReconnect(t *testing.T) {
	simulator := newLossySimulator()

	// start a server and connect one client

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	clientID := randomUint64()

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, clientID)

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// disconnect client on the server-side and wait until client sees the disconnect

	simulator.Reset()

	server.DisconnectClient(0)

	for {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		if client.State() <= ClientStateDisconnected {
			break
		}

		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateDisconnected)
	check(t, !server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 0)

	// now reconnect the client and verify they connect

	simulator.Reset()

	connectToken = generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, clientID)

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)
}

func TestDisableTimeout(t *testing.T) {
	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	// negative timeout disables the timeout entirely (dev only)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, -1, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, client.Index() == 0)
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	serverNumPacketsReceived := 0
	clientNumPacketsReceived := 0

	packetData := make([]byte, MaxPacketSize)
	for i := range packetData {
		packetData[i] = uint8(i)
	}

	for {
		simulator.Update(currentTime)

		client.Update(currentTime)

		server.Update(currentTime)

		client.SendPacket(packetData)

		server.SendPacket(0, packetData)

		for {
			packet, _ := client.ReceivePacket()
			if packet == nil {
				break
			}
			check(t, len(packet) == MaxPacketSize)
			check(t, bytes.Equal(packet, packetData))
			clientNumPacketsReceived++
		}

		for {
			packet, _ := server.ReceivePacket(0)
			if packet == nil {
				break
			}
			check(t, len(packet) == MaxPacketSize)
			check(t, bytes.Equal(packet, packetData))
			serverNumPacketsReceived++
		}

		if clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10 {
			if server.ClientConnected(0) {
				server.DisconnectClient(0)
			}
		}

		if client.State() <= ClientStateDisconnected {
			break
		}

		currentTime += 1000.0 // normally this would timeout the client
	}

	check(t, clientNumPacketsReceived >= 10 && serverNumPacketsReceived >= 10)
}

type testLoopbackContext struct {
	client                         *Client
	server                         *Server
	numLoopbackPacketsSentToClient int
	numLoopbackPacketsSentToServer int
}

func TestLoopback(t *testing.T) {
	var context testLoopbackContext

	simulator := newLossySimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	expectedPacket := make([]byte, MaxPacketSize)
	for i := range expectedPacket {
		expectedPacket[i] = uint8(i)
	}

	// start the server

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
		SendLoopbackPacketCallback: func(clientIndex int, packetData []byte, packetSequence uint64) {
			check(t, clientIndex == 0)
			check(t, bytes.Equal(packetData, expectedPacket))
			context.numLoopbackPacketsSentToClient++
			context.client.ProcessLoopbackPacket(packetData, packetSequence)
		},
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	maxClients := 2

	server.Start(maxClients)

	context.server = server

	// connect a loopback client in slot 0

	clientConfig := &ClientConfig{
		NetworkSimulator: simulator,
		SendLoopbackPacketCallback: func(clientIndex int, packetData []byte, packetSequence uint64) {
			check(t, clientIndex == 0)
			check(t, bytes.Equal(packetData, expectedPacket))
			context.numLoopbackPacketsSentToServer++
			context.server.ProcessLoopbackPacket(clientIndex, packetData, packetSequence)
		},
	}

	loopbackClient, err := NewClient("[::]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer loopbackClient.Close()

	loopbackClient.ConnectLoopback(0, maxClients)
	context.client = loopbackClient

	check(t, loopbackClient.Index() == 0)
	check(t, loopbackClient.Loopback())
	check(t, loopbackClient.MaxClients() == maxClients)
	check(t, loopbackClient.State() == ClientStateConnected)

	clientID := randomUint64()
	server.ConnectLoopbackClient(0, clientID, nil)

	check(t, server.ClientLoopback(0))
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	// connect a regular client in the other slot

	regularClient, err := NewClient("[::]:50001", clientConfig, currentTime)
	check(t, err == nil)
	defer regularClient.Close()

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	regularClient.Connect(connectToken)

	pumpUntilConnected(simulator, regularClient, server, &currentTime, deltaTime)

	check(t, regularClient.State() == ClientStateConnected)
	check(t, regularClient.Index() == 1)
	check(t, server.ClientConnected(0))
	check(t, server.ClientConnected(1))
	check(t, server.ClientLoopback(0))
	check(t, !server.ClientLoopback(1))
	check(t, server.NumConnectedClients() == 2)

	// test that we can exchange packets for the regular client and the loopback client

	exchangePackets := func() (loopbackClientReceived, regularClientReceived, loopbackServerReceived, regularServerReceived int) {
		for {
			simulator.Update(currentTime)

			regularClient.Update(currentTime)

			server.Update(currentTime)

			loopbackClient.SendPacket(expectedPacket)

			regularClient.SendPacket(expectedPacket)

			server.SendPacket(0, expectedPacket)

			server.SendPacket(1, expectedPacket)

			for {
				packet, _ := loopbackClient.ReceivePacket()
				if packet == nil {
					break
				}
				check(t, bytes.Equal(packet, expectedPacket))
				loopbackClientReceived++
			}

			for {
				packet, _ := regularClient.ReceivePacket()
				if packet == nil {
					break
				}
				check(t, bytes.Equal(packet, expectedPacket))
				regularClientReceived++
			}

			for {
				packet, _ := server.ReceivePacket(0)
				if packet == nil {
					break
				}
				check(t, bytes.Equal(packet, expectedPacket))
				loopbackServerReceived++
			}

			for {
				packet, _ := server.ReceivePacket(1)
				if packet == nil {
					break
				}
				check(t, bytes.Equal(packet, expectedPacket))
				regularServerReceived++
			}

			if loopbackClientReceived >= 10 && loopbackServerReceived >= 10 &&
				regularClientReceived >= 10 && regularServerReceived >= 10 {
				break
			}

			if regularClient.State() <= ClientStateDisconnected {
				break
			}

			currentTime += deltaTime
		}
		return
	}

	loopbackClientReceived, regularClientReceived, loopbackServerReceived, regularServerReceived := exchangePackets()

	check(t, loopbackClientReceived >= 10)
	check(t, loopbackServerReceived >= 10)
	check(t, regularClientReceived >= 10)
	check(t, regularServerReceived >= 10)
	check(t, context.numLoopbackPacketsSentToClient >= 10)
	check(t, context.numLoopbackPacketsSentToServer >= 10)

	// verify that we can disconnect the loopback client

	check(t, server.ClientLoopback(0))
	check(t, server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 2)

	server.DisconnectLoopbackClient(0)

	check(t, !server.ClientLoopback(0))
	check(t, !server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 1)

	loopbackClient.DisconnectLoopback()

	check(t, loopbackClient.State() == ClientStateDisconnected)

	// verify that we can reconnect the loopback client

	clientID = randomUint64()
	server.ConnectLoopbackClient(0, clientID, nil)

	check(t, server.ClientLoopback(0))
	check(t, !server.ClientLoopback(1))
	check(t, server.ClientConnected(0))
	check(t, server.ClientConnected(1))
	check(t, server.NumConnectedClients() == 2)

	loopbackClient.ConnectLoopback(0, maxClients)

	check(t, loopbackClient.Index() == 0)
	check(t, loopbackClient.Loopback())
	check(t, loopbackClient.MaxClients() == maxClients)
	check(t, loopbackClient.State() == ClientStateConnected)

	// verify that we can exchange packets for both regular and loopback client post reconnect

	context.numLoopbackPacketsSentToClient = 0
	context.numLoopbackPacketsSentToServer = 0

	loopbackClientReceived, regularClientReceived, loopbackServerReceived, regularServerReceived = exchangePackets()

	check(t, loopbackClientReceived >= 10)
	check(t, loopbackServerReceived >= 10)
	check(t, regularClientReceived >= 10)
	check(t, regularServerReceived >= 10)
	check(t, context.numLoopbackPacketsSentToClient >= 10)
	check(t, context.numLoopbackPacketsSentToServer >= 10)

	// verify the regular client times out but loopback client doesn't

	currentTime += 100000.0

	server.Update(currentTime)

	check(t, server.ClientConnected(0))
	check(t, !server.ClientConnected(1))

	loopbackClient.Update(currentTime)

	check(t, loopbackClient.State() == ClientStateConnected)

	// verify that disconnect all clients leaves loopback clients alone

	server.DisconnectAllClients()

	check(t, server.ClientConnected(0))
	check(t, !server.ClientConnected(1))
	check(t, server.ClientLoopback(0))
}

// TestPacketTagging must run last: packet tagging is enabled process-wide and
// stays on for any sockets created afterwards, exactly as in the C library.
func TestPacketTagging(t *testing.T) {
	// IMPORTANT: Packet tagging is off by default because it doesn't play well with some older home routers
	// See https://learn.microsoft.com/en-us/gaming/gdk/_content/gc/networking/overviews/qos-packet-tagging
	// However, I really recommend providing players with a way to turn it on, since it can significantly reduce
	// jitter playing over Wi-Fi.

	EnablePacketTagging()

	{
		serverAddress := "127.0.0.1:40000"

		server, err := NewServer(serverAddress, nil, 0.0)
		check(t, err == nil)

		client, err := NewClient("127.0.0.1:50000", nil, 0.0)
		check(t, err == nil)

		connectToken := generateTestConnectToken(t, serverAddress, testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

		client.Connect(connectToken)

		client.Close()

		server.Close()
	}

	{
		serverAddress := "[::1]:40000"

		server, err := NewServer(serverAddress, nil, 0.0)
		check(t, err == nil)

		client, err := NewClient("[::1]:50000", nil, 0.0)
		check(t, err == nil)

		connectToken := generateTestConnectToken(t, serverAddress, testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

		client.Connect(connectToken)

		client.Close()

		server.Close()
	}
}

const connectionResponseTimestamp uint64 = 1700000000

// connectionResponseTokens gives the Go and C scripts the same token bytes.
func connectionResponseTokens(t *testing.T) [3][]byte {
	return sharedConnectionResponseTokens(t)
}

func connectionResponseTranscript(t *testing.T, tokenBytes [3][]byte) string {
	t.Helper()
	var tokens [3]connectToken
	for i := range tokens {
		if err := tokens[i].read(tokenBytes[i]); err != nil {
			t.Fatal(err)
		}
	}
	x, err := ParseAddress("[::1]:50000")
	if err != nil {
		t.Fatal(err)
	}
	y, err := ParseAddress("[::1]:50001")
	if err != nil {
		t.Fatal(err)
	}
	type sentPacket struct {
		to Address
		data []byte
	}
	var sent []sentPacket
	server, err := NewServer("[::1]:40000", &ServerConfig{
		ProtocolID: testProtocolID, PrivateKey: testPrivateKey,
		MaxConnectTokenLifetime: 600,
		OverrideSendAndReceive: true,
		SendPacketOverride: func(to *Address, data []byte) {
			sent = append(sent, sentPacket{*to, bytes.Clone(data)})
		},
		ReceivePacketOverride: func() ([]byte, Address, int) {
			return nil, Address{}, 0
		},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.startAt(4, connectionResponseTimestamp-1)
	currentTime := 0.0
	advance := func() {
		server.time = currentTime
		currentTime += 0.1
	}
	request := func(from *Address, token *connectToken) connectionChallenge {
		advance()
		p := &connectionRequest{
			versionInfo: versionInfo,
			protocolID: token.protocolID,
			connectTokenExpireTimestamp: token.expireTimestamp,
			connectTokenNonce: token.nonce,
			connectTokenData: token.privateData,
		}
		var raw [maxPacketBytes]byte
		n := writePacket(p, raw[:], 0, nil, testProtocolID)
		server.processPacketAt(from, raw[:n], connectionResponseTimestamp)
		allowed := [connectionNumPackets]bool{}
		allowed[connectionChallengePacket] = true
		for i := len(sent)-1; i >= 0; i-- {
			if !sent[i].to.Equal(*from) {
				continue
			}
			data := bytes.Clone(sent[i].data)
			var sequence uint64
			p := readPacket(data, &sequence, token.serverToClientKey[:],
				testProtocolID, 0, 0, nil, &allowed, nil)
			if challenge, ok := p.(*connectionChallenge); ok {
				return *challenge
			}
		}
		t.Fatal("no challenge sent")
		return connectionChallenge{}
	}
	response := func(from *Address, token *connectToken, sequence uint64, challenge connectionChallenge) {
		advance()
		p := &connectionResponse{
			challengeTokenSequence: challenge.challengeTokenSequence,
			challengeTokenData: challenge.challengeTokenData,
		}
		var raw [maxPacketBytes]byte
		n := writePacket(p, raw[:], sequence, token.clientToServerKey[:], testProtocolID)
		server.processPacketAt(from, raw[:n], connectionResponseTimestamp)
	}
	var out strings.Builder
	step := func(name string) {
		fmt.Fprintf(&out, "%s connected", name)
		for _, id := range []uint64{0x1111, 0x2222, 0x3333} {
			for slot := 0; slot < server.maxClients; slot++ {
				if server.clientConnected[slot] && server.clientID[slot] == id {
					fmt.Fprintf(&out, " %04x", id)
				}
			}
		}
		out.WriteString(" userdata")
		for _, id := range []uint64{0x1111, 0x2222, 0x3333} {
			for slot := 0; slot < server.maxClients; slot++ {
				if server.clientConnected[slot] && server.clientID[slot] == id {
					fmt.Fprintf(&out, " %02x", server.clientUserData[slot][0])
				}
			}
		}
		out.WriteByte('\n')
	}
	challengeA := request(&x, &tokens[0])
	step("request-a")
	challengeB := request(&y, &tokens[1])
	step("request-b")
	response(&y, &tokens[1], 1, challengeA)
	step("response-b-with-a")
	response(&y, &tokens[1], 2, challengeB)
	step("response-b-with-b")
	challengeCFirst := request(&x, &tokens[2])
	step("request-c-first")
	_ = request(&x, &tokens[2])
	step("request-c-second")
	response(&x, &tokens[2], 1, challengeA)
	step("response-c-with-a")
	response(&x, &tokens[2], 2, challengeCFirst)
	step("response-c-with-c-first")
	return out.String()
}

func TestConnectionResponseRefusesAnotherMappingsChallenge(t *testing.T) {
	got := connectionResponseTranscript(t, connectionResponseTokens(t))
	want := "request-a connected userdata\n" +
		"request-b connected userdata\n" +
		"response-b-with-a connected userdata\n" +
		"response-b-with-b connected 2222 userdata b2\n" +
		"request-c-first connected 2222 userdata b2\n" +
		"request-c-second connected 2222 userdata b2\n" +
		"response-c-with-a connected 2222 userdata b2\n" +
		"response-c-with-c-first connected 2222 3333 userdata b2 c3\n"
	if got != want {
		t.Fatalf("connection response transcript differs:\nwant:\n%s\ngot:\n%s", want, got)
	}
}
