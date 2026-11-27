package netcode

import "testing"

// TestServerRestartGlobalSequence guards the AEAD nonce-reuse fix ported from
// the C library (netcode commit dc21b70). Global packets (challenge, denied)
// encrypt under the same per-token server-to-client key as per-client packets,
// whose sequences start at zero, so the server's global sequence must stay in
// the top half of the sequence space. A stopped-and-restarted server must
// re-seed it, or it reuses nonces.
func TestServerRestartGlobalSequence(t *testing.T) {
	serverConfig := &ServerConfig{
		ProtocolID:             testProtocolID,
		PrivateKey:             testPrivateKey,
		OverrideSendAndReceive: true,
		SendPacketOverride:     testSendPacketOverride,
		ReceivePacketOverride:  testReceivePacketOverride,
	}
	server, err := NewServer("[::1]:40123", serverConfig, 0.0)
	check(t, err == nil)
	defer server.Close()

	// each of the three sites that seed the sequence is checked on its own below,
	// since Start re-seeds unconditionally and would otherwise hide a drop in either
	// of the other two
	if server.globalSequence != 1<<63 {
		t.Fatalf("NewServer did not seed the global sequence: %d", server.globalSequence)
	}

	server.Start(1)

	// advance the global sequence as if global packets were sent, then restart
	server.globalSequence += 10
	server.Stop()

	// Stop has to re-seed on its own, so keep this check even though the one after
	// the restart below looks like it covers the same ground.
	if server.globalSequence != 1<<63 {
		t.Fatalf("Stop did not re-seed the global sequence: %d", server.globalSequence)
	}

	server.Start(1)

	// after a restart the global sequence must be back in the top half, not near zero
	if server.globalSequence != 1<<63 {
		t.Fatalf("Start did not re-seed the global sequence: %d", server.globalSequence)
	}
}

// connectsWithKey runs one client against the server with a connect token made
// with the given private key and reports whether it connected.
func connectsWithKey(t *testing.T, simulator *NetworkSimulator, server *Server, currentTime *float64, privateKey [KeyBytes]byte, clientAddress string) bool {
	t.Helper()

	client, err := NewClient(clientAddress, &ClientConfig{NetworkSimulator: simulator}, *currentTime)
	check(t, err == nil)
	defer client.Close()

	connectToken, err := GenerateConnectToken([]string{"127.0.0.1:40000"}, []string{"127.0.0.1:40000"},
		testConnectTokenExpiry, testTimeoutSeconds, randomUint64(), testProtocolID, privateKey[:], randomUserData())
	check(t, err == nil)

	client.Connect(connectToken)

	pumpUntilConnected(simulator, client, server, currentTime, 1.0/10.0)

	return client.State() == ClientStateConnected
}

func TestServerKeepsOwnConfigAfterCallerClearsIt(t *testing.T) {
	simulator := NewNetworkSimulator()
	currentTime := 1000.0

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	// the caller's struct is the caller's once NewServer returns
	serverConfig.PrivateKey = [KeyBytes]byte{}

	startServerOneSecondEarlier(server, 2)

	check(t, connectsWithKey(t, simulator, server, &currentTime, testPrivateKey, "127.0.0.1:50000"))
	check(t, !connectsWithKey(t, simulator, server, &currentTime, [KeyBytes]byte{}, "127.0.0.1:50001"))
}

func TestServerStartRefusesClosedServer(t *testing.T) {
	simulator := NewNetworkSimulator()
	currentTime := 1000.0

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, currentTime)
	check(t, err == nil)

	server.Close()
	startServerOneSecondEarlier(server, 2)

	check(t, !server.Running())
	check(t, !connectsWithKey(t, simulator, server, &currentTime, [KeyBytes]byte{}, "127.0.0.1:50000"))
}

func TestServerKeepsOwnConfigAcrossRestart(t *testing.T) {
	simulator := NewNetworkSimulator()
	currentTime := 1000.0

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: simulator,
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, currentTime)
	check(t, err == nil)
	defer server.Close()

	var otherKey [KeyBytes]byte
	RandomBytes(otherKey[:])
	serverConfig.PrivateKey = otherKey

	startServerOneSecondEarlier(server, 2)
	server.Stop()
	startServerOneSecondEarlier(server, 2)

	check(t, connectsWithKey(t, simulator, server, &currentTime, testPrivateKey, "127.0.0.1:50000"))
	check(t, !connectsWithKey(t, simulator, server, &currentTime, otherKey, "127.0.0.1:50001"))
}
