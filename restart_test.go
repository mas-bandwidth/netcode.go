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
		ProtocolID: testProtocolID,
		PrivateKey: testPrivateKey,
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
