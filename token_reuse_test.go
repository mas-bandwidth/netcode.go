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

	startServerInThePast(server, 1)

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

	// the connect token is spent. presenting it again from the same address is
	// refused outright: the client remembers the token's MAC and goes straight to
	// invalid connect token without sending a connection request.
	client.Connect(connectToken)

	check(t, client.State() == ClientStateInvalidConnectToken)
	check(t, server.NumConnectedClients() == 0)
}

// TestClientRefusesAReusedConnectToken pins the C fix: a client that connects
// with a token, disconnects, and then presents the same token bytes again
// refuses to connect and goes to INVALID_CONNECT_TOKEN, keeping the previous
// connect token's MAC to detect the repeat.
func TestClientRefusesAReusedConnectToken(t *testing.T) {
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

	startServerInThePast(server, 1)

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, randomUint64())

	client.Connect(connectToken)
	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)
	check(t, client.State() == ClientStateConnected)
	check(t, server.NumConnectedClients() == 1)

	server.DisconnectClient(0)

	for client.State() > ClientStateDisconnected {
		simulator.Update(currentTime)
		client.Update(currentTime)
		server.Update(currentTime)
		currentTime += deltaTime
	}

	check(t, server.NumConnectedClients() == 0)

	// presenting the spent token again is refused outright, without any
	// connection request traffic: the client remembers the token's MAC.
	client.Connect(connectToken)

	check(t, client.State() == ClientStateInvalidConnectToken)
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

	server.Start(1)

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

	// restart the server one maximum lifetime earlier so a full-lifetime token
	// minted now is strictly after the server start and clears the restart floor;
	// a connect token with the maximum lifetime connects (a longer lifetime is
	// refused as over-long)
	startServerInThePast(server, 1)

	validToken := generateTestConnectToken(t, "[::1]:40000", DefaultMaxConnectTokenLifetime, testTimeoutSeconds, randomUint64())

	client.Connect(validToken)

	pumpUntilConnected(simulator, client, server, &currentTime, deltaTime)

	check(t, client.State() == ClientStateConnected)
	check(t, server.NumConnectedClients() == 1)
}

// craftConnectionRequest builds a valid connection request packet for the given
// timeout and expire timestamp, with keys and nonce drawn from the fixed
// connectionResponseTimestamp so the server side can be driven with explicit
// time and no wall clock.
func craftConnectionRequest(t *testing.T, timeoutSeconds int32, expireTimestamp uint64) *connectionRequest {
	t.Helper()

	address, err := ParseAddress("[::1]:40000")
	check(t, err == nil)

	private := connectTokenPrivate{
		clientID:           randomUint64(),
		timeoutSeconds:     timeoutSeconds,
		numServerAddresses: 1,
	}
	private.serverAddresses[0] = address
	RandomBytes(private.clientToServerKey[:])
	RandomBytes(private.serverToClientKey[:])

	token := connectToken{
		protocolID:         testProtocolID,
		createTimestamp:    connectionResponseTimestamp,
		expireTimestamp:    expireTimestamp,
		timeoutSeconds:     timeoutSeconds,
		numServerAddresses: 1,
		clientToServerKey:  private.clientToServerKey,
		serverToClientKey:  private.serverToClientKey,
	}
	token.serverAddresses[0] = address
	RandomBytes(token.nonce[:])
	private.write(token.privateData[:])
	check(t, encryptConnectTokenPrivate(token.privateData[:], token.protocolID, token.expireTimestamp, token.nonce[:], testPrivateKey[:]) == nil)

	return &connectionRequest{
		versionInfo:                 versionInfo,
		protocolID:                  token.protocolID,
		connectTokenExpireTimestamp: token.expireTimestamp,
		connectTokenNonce:           token.nonce,
		connectTokenData:            token.privateData,
	}
}

func TestPreconnectMappingExpiresWithNonpositiveTimeout(t *testing.T) {
	from, err := ParseAddress("[::1]:50000")
	check(t, err == nil)

	newServer := func() *Server {
		server, err := NewServer("[::1]:40000", &ServerConfig{
			ProtocolID:             testProtocolID,
			PrivateKey:             testPrivateKey,
			OverrideSendAndReceive: true,
			SendPacketOverride:     func(*Address, []byte) {},
			ReceivePacketOverride:  func() ([]byte, Address, int) { return nil, Address{}, 0 },
		}, 0)
		check(t, err == nil)
		server.startAt(1, connectionResponseTimestamp-DefaultMaxConnectTokenLifetime)
		return server
	}

	// a request with a negative timeout must not hold an encryption-mapping slot
	// forever: the pre-connect mapping expires after preconnectMappingSeconds
	server := newServer()
	defer server.Close()

	request := craftConnectionRequest(t, -1, connectionResponseTimestamp+DefaultMaxConnectTokenLifetime)
	var raw [maxPacketBytes]byte
	n := writePacket(request, raw[:], 0, nil, testProtocolID)
	server.processPacketAt(&from, raw[:n], connectionResponseTimestamp)
	check(t, server.encryptionManager.findEncryptionMapping(&from, server.time) != -1)

	server.Update(11.0)
	check(t, server.encryptionManager.findEncryptionMapping(&from, server.time) == -1)

	// a request with a zero timeout must still connect when its response arrives
	// one update later, rather than expiring before the response can be sent
	var sent []lifetimeSentPacket
	zeroServer := lifetimeServer(t, &sent)
	defer zeroServer.Close()

	zeroRequest, clientToServerKey, serverToClientKey := lifetimeConnectToken(t, 0, tokenLifetimeTimestamp+DefaultMaxConnectTokenLifetime)
	n = writePacket(zeroRequest, raw[:], 0, nil, testProtocolID)
	zeroServer.time = 0.0
	zeroServer.processPacketAt(&from, raw[:n], tokenLifetimeTimestamp)

	challenge, ok := lifetimeFindChallenge(sent, &from, serverToClientKey)
	check(t, ok)

	zeroServer.time = 0.1
	response := &connectionResponse{
		challengeTokenSequence: challenge.challengeTokenSequence,
		challengeTokenData:     challenge.challengeTokenData,
	}
	n = writePacket(response, raw[:], 1, clientToServerKey[:], testProtocolID)
	zeroServer.processPacketAt(&from, raw[:n], tokenLifetimeTimestamp)
	check(t, zeroServer.NumConnectedClients() == 1)
}

func TestNeverExpiringTokenIsRefused(t *testing.T) {
	t.Parallel()

	const maxLifetime = uint64(DefaultMaxConnectTokenLifetime)
	current := uint64(connectionResponseTimestamp)

	check(t, connectTokenExpireTimestampExceedsLifetime(^uint64(0), current, maxLifetime))
	check(t, connectTokenExpireTimestampExceedsLifetime(current+2*maxLifetime, current, maxLifetime))
	check(t, connectTokenExpireTimestampExceedsLifetime(current+maxLifetime+1, current, maxLifetime))
	check(t, !connectTokenExpireTimestampExceedsLifetime(current+maxLifetime, current, maxLifetime))
	check(t, !connectTokenExpireTimestampExceedsLifetime(current+1, current, maxLifetime))
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

	server.Start(1)

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
