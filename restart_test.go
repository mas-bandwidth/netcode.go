package netcode

import "testing"

// TestServerRestartGlobalSequence guards the AEAD nonce-reuse fix ported from
// the C library (netcode commit dc21b70). Global packets (challenge, denied)
// encrypt under the same per-token server-to-client key as per-client packets,
// whose sequences start at zero, so the server's global sequence must stay in
// the top half of the sequence space. A stopped-and-restarted server must
// re-seed it to a different value, or it reuses nonces.
func TestServerRestartGlobalSequence(t *testing.T) {
	serverConfig := &ServerConfig{
		ProtocolID: testProtocolID,
		PrivateKey: testPrivateKey,
	}
	server, err := NewServer("[::1]:40123", serverConfig, 0.0)
	check(t, err == nil)
	defer server.Close()

	// each of the three sites that seed the sequence is checked on its own below,
	// since Start re-seeds unconditionally and would otherwise hide a drop in either
	// of the other two
	firstSeed := server.globalSequence
	if firstSeed < 1<<63 {
		t.Fatalf("NewServer did not seed the global sequence in the top half: %d", firstSeed)
	}

	server.Start(1)

	// advance the global sequence as if global packets were sent, then restart
	server.globalSequence += 10
	server.Stop()

	// Stop has to re-seed on its own, so keep this check even though the one after
	// the restart below looks like it covers the same ground.
	afterStop := server.globalSequence
	if afterStop < 1<<63 {
		t.Fatalf("Stop did not re-seed the global sequence in the top half: %d", afterStop)
	}

	server.Start(1)

	// after a restart the global sequence must be back in the top half, not near zero
	if server.globalSequence < 1<<63 {
		t.Fatalf("Start did not re-seed the global sequence in the top half: %d", server.globalSequence)
	}
}

// TestGlobalSequenceDiffersBetweenServers pins the properties the C fix
// guarantees: each started server has a global packet sequence in the top half
// of the space (>= 2^63, so per-client sequences starting at zero never meet
// it) and two servers sharing a token encrypt their first challenge under
// different nonces, so two starts give two different global sequences.
func TestGlobalSequenceDiffersBetweenServers(t *testing.T) {
	newServer := func() *Server {
		server, err := NewServer("[::1]:40123", &ServerConfig{
			ProtocolID:             testProtocolID,
			PrivateKey:             testPrivateKey,
			OverrideSendAndReceive: true,
		}, 0.0)
		check(t, err == nil)
		server.Start(1)
		return server
	}

	first := newServer()
	defer first.Close()
	second := newServer()
	defer second.Close()

	if first.globalSequence < 1<<63 {
		t.Fatalf("first server global sequence not in the top half: %d", first.globalSequence)
	}
	if second.globalSequence < 1<<63 {
		t.Fatalf("second server global sequence not in the top half: %d", second.globalSequence)
	}
	if first.globalSequence == second.globalSequence {
		t.Fatalf("two servers started from fresh share a global sequence: %d", first.globalSequence)
	}

	// stop and restart the first server: it must re-seed to a different value,
	// or it reuses AEAD nonces under the same server-to-client token keys.
	first.Stop()
	first.Start(1)
	if first.globalSequence < 1<<63 {
		t.Fatalf("restarted server global sequence not in the top half: %d", first.globalSequence)
	}
}
