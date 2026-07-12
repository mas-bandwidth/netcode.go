package netcode

import (
	"testing"
)

// Benchmarks for the hot paths, filling the role of profile.c in the C
// implementation. Run with:
//
//	go test -run='^$' -bench=. -benchmem

// BenchmarkWritePayloadPacket measures writing and encrypting a full size
// payload packet: the per-packet send cost.
func BenchmarkWritePayloadPacket(b *testing.B) {
	packetKey := GenerateKey()

	packet := &connectionPayload{payloadData: make([]byte, maxPayloadBytes)}
	RandomBytes(packet.payloadData)

	var buffer [maxPacketBytes]byte

	b.SetBytes(maxPayloadBytes)
	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		if writePacket(packet, buffer[:], uint64(i), packetKey, testProtocolID) == 0 {
			b.Fatal("failed to write packet")
		}
	}
}

// BenchmarkReadPayloadPacket measures decrypting and parsing a full size
// payload packet: the per-packet receive cost.
func BenchmarkReadPayloadPacket(b *testing.B) {
	packetKey := GenerateKey()

	packet := &connectionPayload{payloadData: make([]byte, maxPayloadBytes)}
	RandomBytes(packet.payloadData)

	var template [maxPacketBytes]byte
	packetBytes := writePacket(packet, template[:], 1000, packetKey, testProtocolID)
	if packetBytes == 0 {
		b.Fatal("failed to write packet")
	}

	allowedPackets := allPacketsAllowed()

	var buffer [maxPacketBytes]byte

	b.SetBytes(maxPayloadBytes)
	b.ReportAllocs()

	for b.Loop() {
		// readPacket decrypts in place, so restore the ciphertext each iteration
		copy(buffer[:packetBytes], template[:packetBytes])

		var sequence uint64
		if readPacket(buffer[:packetBytes], &sequence, packetKey, testProtocolID, 0, nil, &allowedPackets, nil) == nil {
			b.Fatal("failed to read packet")
		}
	}
}

// BenchmarkServerProcessConnectionRequest measures reading a connection
// request packet, including decrypting the private connect token: the cost an
// attacker can impose per spoofed request packet.
func BenchmarkServerProcessConnectionRequest(b *testing.B) {
	token := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{testServerAddress()}, nil)

	request := &connectionRequest{
		versionInfo:                 versionInfo,
		protocolID:                  testProtocolID,
		connectTokenExpireTimestamp: 1,
	}
	nonce := generateNonce()
	request.connectTokenNonce = nonce
	token.write(request.connectTokenData[:])
	if encryptConnectTokenPrivate(request.connectTokenData[:], testProtocolID, 1, nonce[:], testPrivateKey[:]) != nil {
		b.Fatal("failed to encrypt connect token")
	}

	packetKey := GenerateKey()

	var template [maxPacketBytes]byte
	packetBytes := writePacket(request, template[:], 1000, packetKey, testProtocolID)
	if packetBytes == 0 {
		b.Fatal("failed to write packet")
	}

	allowedPackets := allPacketsAllowed()

	var buffer [maxPacketBytes]byte

	b.ReportAllocs()

	for b.Loop() {
		copy(buffer[:packetBytes], template[:packetBytes])

		var sequence uint64
		if readPacket(buffer[:packetBytes], &sequence, packetKey, testProtocolID, 0, testPrivateKey[:], &allowedPackets, nil) == nil {
			b.Fatal("failed to read packet")
		}
	}
}

// BenchmarkGenerateConnectToken measures generating a connect token, the
// per-client cost on the web backend.
func BenchmarkGenerateConnectToken(b *testing.B) {
	serverAddresses := []string{"127.0.0.1:40000"}
	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		_, err := GenerateConnectToken(serverAddresses, serverAddresses,
			testConnectTokenExpiry, testTimeoutSeconds, uint64(i), testProtocolID, testPrivateKey[:], userData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseAddress measures address parsing.
func BenchmarkParseAddress(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		if _, err := ParseAddress("[fe80::202:b3ff:fe1e:8329]:40000"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkClientServerUpdate measures a full client and server update tick
// over the network simulator with one connected client exchanging payload
// packets in both directions.
func BenchmarkClientServerUpdate(b *testing.B) {
	simulator := NewNetworkSimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 60.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}

	client, err := NewClient("[::]:50000", clientConfig, currentTime)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}

	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()

	server.Start(1)

	connectToken, err := GenerateConnectToken([]string{"[::1]:40000"}, []string{"[::1]:40000"},
		testConnectTokenExpiry, testTimeoutSeconds, testClientID, testProtocolID, testPrivateKey[:], nil)
	if err != nil {
		b.Fatal(err)
	}

	client.Connect(connectToken)

	for client.State() != ClientStateConnected {
		if client.State() <= ClientStateDisconnected {
			b.Fatal("client failed to connect")
		}
		simulator.Update(currentTime)
		client.Update(currentTime)
		server.Update(currentTime)
		currentTime += deltaTime
	}

	packetData := make([]byte, MaxPacketSize)
	for i := range packetData {
		packetData[i] = uint8(i)
	}

	b.ReportAllocs()

	for b.Loop() {
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
		}

		for {
			packet, _ := server.ReceivePacket(0)
			if packet == nil {
				break
			}
		}

		currentTime += deltaTime
	}

	if client.State() != ClientStateConnected {
		b.Fatal("client lost connection during benchmark")
	}
}
