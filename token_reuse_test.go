package netcode

import (
	"sync"
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
		var salt [connectSaltBytes]byte
		mac[0] = uint8(i + 1)
		mac[1] = uint8((i + 1) >> 8)
		idx := connectTokenEntriesFindOrAdd(&server.connectTokenEntries, &dummyAddress, mac[:], salt, expireTimestamp, currentTimestamp, 100.0, testTimeoutSeconds)
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
	RandomBytes(request.clientSalt[:])
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

type nonceAuditor struct {
	mu      sync.Mutex
	seen    map[[KeyBytes + 12]byte]int
	pairs   int
	repeats int
}

func startNonceAudit(t *testing.T) *nonceAuditor {
	t.Helper()
	auditor := &nonceAuditor{
		seen: make(map[[KeyBytes + 12]byte]int),
	}
	previous := auditPacketNonce
	auditPacketNonce = func(key [KeyBytes]byte, nonce [12]byte) {
		var pair [KeyBytes + 12]byte
		copy(pair[:KeyBytes], key[:])
		copy(pair[KeyBytes:], nonce[:])
		auditor.mu.Lock()
		auditor.pairs++
		if auditor.seen[pair] > 0 {
			auditor.repeats++
		}
		auditor.seen[pair]++
		auditor.mu.Unlock()
	}
	t.Cleanup(func() {
		auditPacketNonce = previous
		auditor.mu.Lock()
		repeats := auditor.repeats
		auditor.mu.Unlock()
		if repeats != 0 {
			t.Errorf("AEAD nonce audit detected %d repeated (key, nonce) pairs", repeats)
		}
	})
	return auditor
}

func (a *nonceAuditor) stats() (pairs, repeats int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pairs, a.repeats
}

type testWireHarness struct {
	client                      *Client
	server                      *Server
	clientAddress               Address
	serverAddress               Address
	shuttingDown                bool
	dropServerPackets           int
	dropClientRequestPackets    bool
	dropClientResponsePackets   bool
	dropClientDisconnectPackets bool
	numConnectionRequests       int
	numConnectionResponses      int
	challengePacket             []byte
}

func newTestWireHarness(t *testing.T) *testWireHarness {
	t.Helper()
	w := &testWireHarness{}

	var err error
	w.clientAddress, err = ParseAddress("[::1]:50000")
	check(t, err == nil)
	w.serverAddress, err = ParseAddress("[::1]:40000")
	check(t, err == nil)

	clientConfig := &ClientConfig{
		OverrideSendAndReceive: true,
		SendPacketOverride: func(to *Address, packetData []byte) {
			if w.shuttingDown || len(packetData) == 0 {
				return
			}
			if packetData[0] == connectionRequestPacket {
				w.numConnectionRequests++
				if w.dropClientRequestPackets {
					return
				}
			}
			if packetData[0]&0xF == connectionResponsePacket {
				w.numConnectionResponses++
				if w.dropClientResponsePackets {
					return
				}
			}
			if packetData[0]&0xF == connectionDisconnectPacket {
				if w.dropClientDisconnectPackets {
					return
				}
			}
			copied := append([]byte(nil), packetData...)
			w.server.ProcessPacket(&w.clientAddress, copied)
		},
		ReceivePacketOverride: testReceivePacketOverride,
	}
	w.client, err = NewClient("[::1]:50000", clientConfig, 0.0)
	check(t, err == nil)

	serverConfig := &ServerConfig{
		ProtocolID:             testProtocolID,
		PrivateKey:             testPrivateKey,
		OverrideSendAndReceive: true,
		SendPacketOverride: func(to *Address, packetData []byte) {
			if w.shuttingDown || len(packetData) == 0 {
				return
			}
			if packetData[0]&0xF == connectionChallengePacket && len(w.challengePacket) == 0 {
				w.challengePacket = append([]byte(nil), packetData...)
			}
			if w.dropServerPackets > 0 {
				w.dropServerPackets--
				return
			}
			copied := append([]byte(nil), packetData...)
			w.client.ProcessPacket(&w.serverAddress, copied)
		},
		ReceivePacketOverride: testReceivePacketOverride,
	}
	w.server, err = NewServer("[::1]:40000", serverConfig, 0.0)
	check(t, err == nil)

	startServerOneSecondEarlier(w.server, 1)

	t.Cleanup(func() {
		w.shuttingDown = true
		w.server.Close()
		w.client.Close()
	})

	return w
}

func (w *testWireHarness) connectClient(t *testing.T, connectToken []byte, currentTime *float64, deltaTime float64) {
	t.Helper()
	w.client.Connect(connectToken)
	for {
		w.client.Update(*currentTime)
		w.server.Update(*currentTime)
		if w.client.State() <= ClientStateDisconnected || w.client.State() == ClientStateConnected {
			break
		}
		*currentTime += deltaTime
		check(t, *currentTime < 100.0)
	}
}

func TestClientReconnectAfterUnfinishedHandshake(t *testing.T) {
	auditor := startNonceAudit(t)
	wire := newTestWireHarness(t)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, testClientID)

	// attempt 1: drop every connection response until the client times out
	wire.dropClientResponsePackets = true
	wire.connectClient(t, connectToken, &currentTime, deltaTime)

	check(t, wire.client.State() == ClientStateConnectionResponseTimedOut)
	check(t, wire.numConnectionResponses >= 2)
	check(t, wire.server.NumConnectedClients() == 0)

	// attempt 2: retry with the same connect token after the unfinished handshake timed out
	wire.dropClientResponsePackets = false
	wire.connectClient(t, connectToken, &currentTime, deltaTime)

	check(t, wire.client.State() == ClientStateConnectionRequestTimedOut)
	check(t, wire.server.NumConnectedClients() == 0)

	pairs, repeats := auditor.stats()
	check(t, pairs > 0)
	check(t, repeats == 0)
}

func TestClientReconnectAfterAbortedHandshake(t *testing.T) {
	auditor := startNonceAudit(t)
	wire := newTestWireHarness(t)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, testClientID)

	// attempt 1: drop connection responses, then explicitly abort before timeout
	wire.dropClientResponsePackets = true
	wire.client.Connect(connectToken)

	for wire.numConnectionResponses < 2 {
		wire.client.Update(currentTime)
		wire.server.Update(currentTime)
		currentTime += deltaTime
		check(t, currentTime < 2.0)
	}

	check(t, wire.client.State() == ClientStateSendingConnectionResponse)

	wire.client.Disconnect()
	wire.server.Update(currentTime)

	check(t, wire.client.State() == ClientStateDisconnected)
	check(t, wire.server.NumConnectedClients() == 0)
	check(t, wire.server.encryptionManager.findEncryptionMapping(&wire.clientAddress, currentTime) == -1)

	// attempt 2: immediate retry with the same connect token is refused
	wire.dropClientResponsePackets = false
	wire.connectClient(t, connectToken, &currentTime, deltaTime)

	check(t, wire.client.State() == ClientStateConnectionRequestTimedOut)
	check(t, wire.server.NumConnectedClients() == 0)

	pairs, repeats := auditor.stats()
	check(t, pairs > 0)
	check(t, repeats == 0)
}

func TestClientReconnectSubTimeoutPacketLoss(t *testing.T) {
	auditor := startNonceAudit(t)
	wire := newTestWireHarness(t)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, testClientID)

	// attempt 1: drop both connection responses and disconnect packets so the server's
	// pending entry and half-open mapping remain live and sub-timeout
	wire.dropClientResponsePackets = true
	wire.dropClientDisconnectPackets = true
	wire.client.Connect(connectToken)

	for wire.numConnectionResponses < 2 {
		wire.client.Update(currentTime)
		wire.server.Update(currentTime)
		currentTime += deltaTime
		check(t, currentTime < 2.0)
	}

	wire.client.Disconnect()
	wire.server.Update(currentTime)

	check(t, wire.server.encryptionManager.findEncryptionMapping(&wire.clientAddress, currentTime) != -1)

	// attempt 2: sub-timeout reconnect with the same connect token carries a fresh clientSalt,
	// so the pending entry refuses it and zero (key, nonce) pairs repeat
	wire.dropClientResponsePackets = false
	wire.dropClientDisconnectPackets = false
	wire.connectClient(t, connectToken, &currentTime, deltaTime)

	check(t, wire.client.State() == ClientStateConnectionRequestTimedOut)
	check(t, wire.server.NumConnectedClients() == 0)

	pairs, repeats := auditor.stats()
	check(t, pairs > 0)
	check(t, repeats == 0)
}

func TestClientReplayedChallengeOnReusedToken(t *testing.T) {
	auditor := startNonceAudit(t)
	wire := newTestWireHarness(t)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, testClientID)

	wire.dropClientResponsePackets = true
	wire.dropClientDisconnectPackets = true
	wire.client.Connect(connectToken)

	for wire.numConnectionResponses < 2 {
		wire.client.Update(currentTime)
		wire.server.Update(currentTime)
		currentTime += deltaTime
		check(t, currentTime < 2.0)
	}

	check(t, len(wire.challengePacket) > 0)

	wire.client.Disconnect()

	// attempt 2: hold the client in SendingConnectionRequest by dropping outgoing requests,
	// then replay attempt 1's challenge packet. AEAD fails under the fresh clientSalt.
	responsesBeforeReplay := wire.numConnectionResponses

	wire.dropClientRequestPackets = true
	wire.dropClientResponsePackets = false
	wire.dropClientDisconnectPackets = false

	wire.client.Connect(connectToken)
	wire.client.Update(currentTime)

	check(t, wire.client.State() == ClientStateSendingConnectionRequest)
	check(t, !wire.client.hasServerNonce)

	replayedChallenge := append([]byte(nil), wire.challengePacket...)
	wire.client.ProcessPacket(&wire.serverAddress, replayedChallenge)

	check(t, wire.client.State() == ClientStateSendingConnectionRequest)
	check(t, !wire.client.hasServerNonce)

	currentTime += deltaTime
	wire.client.Update(currentTime)

	check(t, wire.client.State() == ClientStateSendingConnectionRequest)
	check(t, wire.numConnectionResponses == responsesBeforeReplay)

	pairs, repeats := auditor.stats()
	check(t, pairs > 0)
	check(t, repeats == 0)
}

func TestMultipleServersNonceDisjoint(t *testing.T) {
	auditor := startNonceAudit(t)

	clientAddress, err := ParseAddress("[::1]:50000")
	check(t, err == nil)
	server1Address, err := ParseAddress("[::1]:40000")
	check(t, err == nil)
	server2Address, err := ParseAddress("[::1]:40001")
	check(t, err == nil)

	var (
		client                   *Client
		server1                  *Server
		server2                  *Server
		shuttingDown             bool
		numDeniedFromServer1     int
		numChallengesFromServer2 int
		saltToServer1            [connectSaltBytes]byte
		saltToServer2            [connectSaltBytes]byte
		sawSaltToServer1         bool
		sawSaltToServer2         bool
	)

	clientConfig := &ClientConfig{
		OverrideSendAndReceive: true,
		SendPacketOverride: func(to *Address, packetData []byte) {
			if shuttingDown || len(packetData) == 0 {
				return
			}
			copied := append([]byte(nil), packetData...)
			if to.Equal(server1Address) {
				if copied[0] == connectionRequestPacket && len(copied) == connectionRequestPacketBytes {
					copy(saltToServer1[:], copied[connectionRequestPacketBytes-connectSaltBytes:])
					sawSaltToServer1 = true
				}
				server1.ProcessPacket(&clientAddress, copied)
			} else if to.Equal(server2Address) {
				if copied[0] == connectionRequestPacket && len(copied) == connectionRequestPacketBytes {
					copy(saltToServer2[:], copied[connectionRequestPacketBytes-connectSaltBytes:])
					sawSaltToServer2 = true
				}
				server2.ProcessPacket(&clientAddress, copied)
			}
		},
		ReceivePacketOverride: testReceivePacketOverride,
	}
	client, err = NewClient("[::1]:50000", clientConfig, 0.0)
	check(t, err == nil)

	server1Config := &ServerConfig{
		ProtocolID:                 testProtocolID,
		PrivateKey:                 testPrivateKey,
		SendLoopbackPacketCallback: func(clientIndex int, packetData []byte, packetSequence uint64) {},
		OverrideSendAndReceive:     true,
		SendPacketOverride: func(to *Address, packetData []byte) {
			if shuttingDown || len(packetData) == 0 {
				return
			}
			if packetData[0]&0xF == connectionDeniedPacket {
				numDeniedFromServer1++
			}
			copied := append([]byte(nil), packetData...)
			client.ProcessPacket(&server1Address, copied)
		},
		ReceivePacketOverride: testReceivePacketOverride,
	}
	server1, err = NewServer("[::1]:40000", server1Config, 0.0)
	check(t, err == nil)

	server2Config := &ServerConfig{
		ProtocolID:             testProtocolID,
		PrivateKey:             testPrivateKey,
		OverrideSendAndReceive: true,
		SendPacketOverride: func(to *Address, packetData []byte) {
			if shuttingDown || len(packetData) == 0 {
				return
			}
			if packetData[0]&0xF == connectionChallengePacket {
				numChallengesFromServer2++
			}
			copied := append([]byte(nil), packetData...)
			client.ProcessPacket(&server2Address, copied)
		},
		ReceivePacketOverride: testReceivePacketOverride,
	}
	server2, err = NewServer("[::1]:40001", server2Config, 0.0)
	check(t, err == nil)

	t.Cleanup(func() {
		shuttingDown = true
		server1.Close()
		server2.Close()
		client.Close()
	})

	startServerOneSecondEarlier(server1, 1)
	startServerOneSecondEarlier(server2, 1)

	// fill server1's single slot via loopback so server1.globalSequence stays at 1 << 63
	server1.ConnectLoopbackClient(0, 100, nil)
	check(t, server1.NumConnectedClients() == 1)
	check(t, server1.globalSequence == 1<<63)
	check(t, server2.globalSequence == 1<<63)

	serverAddresses := []string{"[::1]:40000", "[::1]:40001"}
	connectToken, err := GenerateConnectToken(serverAddresses, serverAddresses,
		testConnectTokenExpiry, testTimeoutSeconds, testClientID, testProtocolID, testPrivateKey[:], randomUserData())
	check(t, err == nil)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	client.Connect(connectToken)

	for {
		client.Update(currentTime)
		server1.Update(currentTime)
		server2.Update(currentTime)

		if client.State() <= ClientStateDisconnected || client.State() == ClientStateConnected {
			break
		}

		currentTime += deltaTime
		check(t, currentTime < 10.0)
	}

	// server1 emitted connectionDenied at globalSequence 2^63 and server2 emitted
	// connectionChallenge at globalSequence 2^63 for the same connect token, under
	// distinct HChaCha20-derived per-connection keys and distinct clientSalts.
	check(t, sawSaltToServer1 && sawSaltToServer2)
	check(t, saltToServer1 != saltToServer2)
	check(t, numDeniedFromServer1 >= 1)
	check(t, numChallengesFromServer2 >= 1)
	check(t, server1.globalSequence == (1<<63)+1)
	check(t, server2.globalSequence > (1<<63))
	check(t, client.State() == ClientStateConnected)
	check(t, server2.NumConnectedClients() == 1)

	pairs, repeats := auditor.stats()
	check(t, pairs >= 3)
	check(t, repeats == 0)
}

func TestClientResponseStateDeniedRequiresMatchingServerNonce(t *testing.T) {
	auditor := startNonceAudit(t)
	wire := newTestWireHarness(t)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	connectTokenData := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, testClientID)

	wire.dropClientResponsePackets = true
	wire.client.Connect(connectTokenData)

	for wire.client.State() != ClientStateSendingConnectionResponse {
		wire.client.Update(currentTime)
		wire.server.Update(currentTime)
		currentTime += deltaTime
		check(t, currentTime < 2.0)
	}

	check(t, wire.client.hasServerNonce)

	// A denied packet encrypted under the locked readPacketKey (which requires matching
	// 30-byte AAD) with a mismatched serverNonce is rejected by both AAD and processPacketInternal.
	wrongNonce := wire.client.serverNonce
	wrongNonce[0] ^= 0xFF
	var buf [maxPacketBytes]byte
	n := writePacket(&connectionDenied{serverNonce: wrongNonce}, buf[:], (1<<63)+99, wire.client.readPacketKey[:], testProtocolID)
	check(t, n > 0)
	wire.client.ProcessPacket(&wire.serverAddress, append([]byte(nil), buf[:n]...))
	wire.client.Update(currentTime)
	check(t, wire.client.State() == ClientStateSendingConnectionResponse)

	// Direct internal check: even if a connectionDenied struct reached processPacketInternal with
	// a mismatched serverNonce, SendingConnectionResponse ignores it.
	wire.client.processPacketInternal(&wire.serverAddress, &connectionDenied{serverNonce: wrongNonce}, (1<<63)+100)
	check(t, !wire.client.shouldDisconnect)

	// Matching serverNonce encrypted under the locked readPacketKey transitions to ConnectionDenied.
	n = writePacket(&connectionDenied{serverNonce: wire.client.serverNonce}, buf[:], (1<<63)+101, wire.client.readPacketKey[:], testProtocolID)
	check(t, n > 0)
	wire.client.ProcessPacket(&wire.serverAddress, append([]byte(nil), buf[:n]...))
	currentTime += deltaTime
	wire.client.Update(currentTime)
	check(t, wire.client.State() == ClientStateConnectionDenied)

	_, repeats := auditor.stats()
	check(t, repeats == 0)
}

func TestServerRetransmittedRequestReusesHalfOpenMapping(t *testing.T) {
	auditor := startNonceAudit(t)
	wire := newTestWireHarness(t)

	currentTime := 0.0
	deltaTime := 1.0 / 10.0

	// Drop the first server challenge packet so the client retransmits its connection request
	// with the same (mac, clientSalt), and verify the server reuses the same serverNonce.
	wire.dropServerPackets = 1
	var observedServerNonces [][serverNonceBytes]byte

	baseSend := wire.server.config.SendPacketOverride
	wire.server.config.SendPacketOverride = func(to *Address, packetData []byte) {
		if len(packetData) > 0 && packetData[0]&0xF == connectionChallengePacket {
			seqBytes := int(packetData[0] >> 4)
			var sn [serverNonceBytes]byte
			copy(sn[:], packetData[1+seqBytes:1+seqBytes+serverNonceBytes])
			observedServerNonces = append(observedServerNonces, sn)
		}
		baseSend(to, packetData)
	}

	connectToken := generateTestConnectToken(t, "[::1]:40000", testConnectTokenExpiry, testTimeoutSeconds, testClientID)
	wire.connectClient(t, connectToken, &currentTime, deltaTime)

	check(t, wire.client.State() == ClientStateConnected)
	check(t, wire.numConnectionRequests >= 2)
	check(t, len(observedServerNonces) >= 2)
	check(t, observedServerNonces[0] == observedServerNonces[1])

	_, repeats := auditor.stats()
	check(t, repeats == 0)
}
