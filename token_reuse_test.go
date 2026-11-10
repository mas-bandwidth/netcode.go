package netcode

import (
	"testing"
)

func TestClientReconnectWithUsedConnectToken(t *testing.T) {
	simulator := NewNetworkSimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}
	client, err := NewClient("[::1]:50000", clientConfig, currentTime)
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

	startServerOneSecondEarlier(server, 1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, server.NumConnectedClients() == 1)

	// disconnect the client server side and wait until client sees it
	server.DisconnectClient(0)

	for client.State() > ClientStateDisconnected {
		simulator.Update(currentTime)
		client.Update(currentTime)
		server.Update(currentTime)
		currentTime += deltaTime
	}

	check(t, server.NumConnectedClients() == 0)

	// the connect token is spent. presenting it again from the same address connects nothing:
	// the client runs out of connection request retries instead
	client.Connect(connectToken)

	for client.State() > ClientStateDisconnected && client.State() != ClientStateConnected {
		simulator.Update(currentTime)
		client.Update(currentTime)
		server.Update(currentTime)
		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnectionRequestTimedOut)
	check(t, server.NumConnectedClients() == 0)
}

func TestClientConnectTokenPredatesServerStart(t *testing.T) {
	simulator := NewNetworkSimulator()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	clientConfig := &ClientConfig{NetworkSimulator: simulator}
	client, err := NewClient("[::1]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:              testProtocolID,
		PrivateKey:              testPrivateKey,
		NetworkSimulator:        simulator,
		MaxConnectTokenLifetime: DefaultMaxConnectTokenLifetime,
	}
	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	startServerOneSecondEarlier(server, 1)

	// a connect token with a shorter lifetime than the server's configured maximum expires
	// earlier than any connect token the backend could have issued after the server started,
	// which is exactly the shape of a connect token issued before it started
	predatingToken := generateTestConnectToken(t, "[::1]:40000", DefaultMaxConnectTokenLifetime-10, testTimeoutSeconds, randomUint64())

	client.Connect(predatingToken)

	for client.State() > ClientStateDisconnected && client.State() != ClientStateConnected {
		simulator.Update(currentTime)
		client.Update(currentTime)
		server.Update(currentTime)
		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnectionRequestTimedOut)
	check(t, server.NumConnectedClients() == 0)

	// a connect token with the full lifetime connects
	validToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(validToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, server.NumConnectedClients() == 1)
}

func TestClientConnectTokenReuseAcrossServerRestart(t *testing.T) {
	const lifetime = DefaultMaxConnectTokenLifetime
	const startTime = testNowUnix

	clock := startTime
	previousNowUnix := nowUnix
	nowUnix = func() uint64 { return clock }
	defer func() { nowUnix = previousNowUnix }()

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	simulator := NewNetworkSimulator()

	clientConfig := &ClientConfig{NetworkSimulator: simulator}
	client, err := NewClient("[::1]:50000", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	serverConfig := &ServerConfig{
		ProtocolID:              testProtocolID,
		PrivateKey:              testPrivateKey,
		NetworkSimulator:        simulator,
		MaxConnectTokenLifetime: lifetime,
	}
	server, err := NewServer("[::1]:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	// Issue the token one second after the first start so its first use is
	// accepted.
	clock = startTime + 1

	connectTokenData, err := GenerateConnectToken([]string{"[::1]:40000"}, []string{"[::1]:40000"},
		lifetime, testTimeoutSeconds, randomUint64(), testProtocolID, testPrivateKey[:], randomUserData())
	check(t, err == nil)

	var parsed connectToken
	check(t, parsed.read(connectTokenData) == nil)
	check(t, parsed.expireTimestamp == clock+uint64(lifetime))

	client.Connect(connectTokenData)
	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)
	check(t, client.State() == ClientStateConnected)
	check(t, server.NumConnectedClients() == 1)

	server.Stop()
	simulator.Reset()

	// Restart in the token's creation second, so its expiry sits exactly at
	// the new start boundary and the token must be refused.
	server.Start(1)
	check(t, server.minConnectTokenExpireTimestamp == parsed.expireTimestamp)

	client.Connect(connectTokenData)
	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnectionRequestTimedOut)
	check(t, server.NumConnectedClients() == 0)
}

func TestConnectTokenHistoryFullServerRefusal(t *testing.T) {
	simulator := NewNetworkSimulator()

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

	startServerOneSecondEarlier(server, 1)

	// Fill all connect token history entries with unexpired tokens
	dummyAddress, err := ParseAddress("[::1]:50000")
	check(t, err == nil)

	expireTimestamp := server.minConnectTokenExpireTimestamp + 100
	currentTimestamp := uint64(1000)

	for i := 0; i < maxConnectTokenEntries; i++ {
		var mac [MacBytes]byte
		mac[0] = uint8(i + 1)
		mac[1] = uint8((i + 1) >> 8)
		idx := connectTokenEntriesFindOrAdd(&server.connectTokenEntries, &dummyAddress, mac[:], expireTimestamp, currentTimestamp, 100.0)
		check(t, idx >= 0)
	}

	// Now try to connect a client: history is full, request must be ignored
	clientConfig := &ClientConfig{NetworkSimulator: simulator}
	client, err := NewClient("[::1]:50001", clientConfig, currentTime)
	check(t, err == nil)
	defer client.Close()

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())
	client.Connect(connectToken)

	for client.State() > ClientStateDisconnected && client.State() != ClientStateConnected {
		simulator.Update(currentTime)
		client.Update(currentTime)
		server.Update(currentTime)
		currentTime += deltaTime
	}

	check(t, client.State() == ClientStateConnectionRequestTimedOut)
	check(t, server.NumConnectedClients() == 0)
}

func TestProcessConnectionRequestUsesPacketTimestamp(t *testing.T) {
	simulator := NewNetworkSimulator()

	server, err := NewServer("[::1]:40000", &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}, 0.0)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)
	defer server.Stop()

	from, err := ParseAddress("[::1]:50000")
	check(t, err == nil)

	// the packet timestamp is one second before the token expires. the history
	// already holds a different token that expires at the token timestamp.
	expireTimestamp := server.minConnectTokenExpireTimestamp + 100
	readTimestamp := expireTimestamp - 1

	previousEntry := connectTokenEntry{
		state:           connectTokenEntryConsumed,
		time:            100.0,
		expireTimestamp: expireTimestamp,
		address:         from,
	}
	previousEntry.mac[0] = 0xAA
	server.connectTokenEntries[0] = previousEntry

	connectToken := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{server.address}, nil)

	request := &connectionRequest{
		versionInfo:                 versionInfo,
		protocolID:                  testProtocolID,
		connectTokenExpireTimestamp: expireTimestamp,
	}
	request.connectTokenNonce = generateNonce()
	connectToken.write(request.connectTokenData[:])
	check(t, encryptConnectTokenPrivate(request.connectTokenData[:], testProtocolID, expireTimestamp, request.connectTokenNonce[:], testPrivateKey[:]) == nil)

	var packetData [maxPacketBytes]byte
	packetBytes := writePacket(request, packetData[:], 0, nil, testProtocolID)
	check(t, packetBytes > 0)

	// the clock has ticked to the token timestamp, but the packet was read at
	// the earlier timestamp and that same timestamp must be used throughout.
	previousNowUnix := nowUnix
	nowUnix = func() uint64 { return expireTimestamp }
	defer func() { nowUnix = previousNowUnix }()

	allowedPackets := serverAllowedPackets()
	server.readAndProcessPacket(&from, packetData[:packetBytes], readTimestamp, &allowedPackets)

	check(t, server.connectTokenEntries[0] == previousEntry)
	check(t, server.connectTokenEntries[1].state == connectTokenEntryPending)
}
