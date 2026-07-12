package netcode

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Live interoperability tests against the C reference implementation. These
// run real handshakes and payload exchange over UDP loopback between this
// implementation and the C example client and server binaries, in both
// directions. Together with the golden vectors in wire_compat_test.go this
// proves the two implementations remain wire compatible.
//
// Set NETCODE_C_BIN_DIR to the bin directory of a built checkout of
// https://github.com/mas-bandwidth/netcode to run these, e.g.
//
//	NETCODE_C_BIN_DIR=$HOME/netcode/build/bin go test -run TestCInterop -v
//
// otherwise they are skipped. The CI wire-compat job builds the C
// implementation from source and runs them on every pull request.

const cInteropTimeout = 30 * time.Second

// The C example client and server use this address when passed as argv[1],
// this private key (the well known netcode test key, testPrivateKey), and
// protocol id 0x1122334455667788 (testProtocolID).

func cInteropBinary(t *testing.T, name string) string {
	t.Helper()

	binDir := os.Getenv("NETCODE_C_BIN_DIR")
	if binDir == "" {
		t.Skip("set NETCODE_C_BIN_DIR to the C implementation's built bin directory to run C interop tests")
	}

	binary := filepath.Join(binDir, name)
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("C %s binary not found: %v", name, err)
	}
	return binary
}

// startCBinary starts a C example binary and arranges for it to be killed and
// its output logged when the test ends.
func startCBinary(t *testing.T, binary string, args ...string) {
	t.Helper()

	var output bytes.Buffer

	cmd := exec.Command(binary, args...)
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start %s: %v", binary, err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", binary, output.String())
		}
	})
}

func cInteropPayload() []byte {
	// the C examples send and assert payload packets of MaxPacketSize bytes
	// filled with this pattern
	payload := make([]byte, MaxPacketSize)
	for i := range payload {
		payload[i] = uint8(i)
	}
	return payload
}

// TestCInteropClientConnectsToCServer connects this implementation's client to
// the C server and requires a full handshake plus payload packets flowing in
// both directions: the connect token generated here must decrypt in C, and the
// challenge/response, keep-alive and payload packets must round trip between
// the two implementations.
func TestCInteropClientConnectsToCServer(t *testing.T) {
	serverBinary := cInteropBinary(t, "server")

	serverAddress := "127.0.0.1:40100"

	startCBinary(t, serverBinary, serverAddress)

	client, err := NewClient("0.0.0.0:0", nil, 0.0)
	check(t, err == nil)
	defer client.Close()

	connectToken, err := GenerateConnectToken([]string{serverAddress}, []string{serverAddress},
		testConnectTokenExpiry, testTimeoutSeconds, randomUint64(), testProtocolID, testPrivateKey[:], randomUserData())
	check(t, err == nil)

	client.Connect(connectToken)

	payload := cInteropPayload()
	payloadPacketsReceived := 0

	start := time.Now()
	deadline := start.Add(cInteropTimeout)

	for time.Now().Before(deadline) {
		currentTime := time.Since(start).Seconds()

		client.Update(currentTime)

		if client.State() == ClientStateConnected {
			client.SendPacket(payload)
		}

		for {
			packet, _ := client.ReceivePacket()
			if packet == nil {
				break
			}
			check(t, bytes.Equal(packet, payload))
			payloadPacketsReceived++
		}

		if client.State() <= ClientStateDisconnected {
			t.Fatalf("client failed to connect to C server: %s", ClientStateName(client.State()))
		}

		if client.State() == ClientStateConnected && payloadPacketsReceived >= 10 {
			return // success: connected to the C server and exchanged payload packets
		}

		time.Sleep(time.Second / 60)
	}

	t.Fatalf("timed out: client state %q, %d payload packets received from C server",
		ClientStateName(client.State()), payloadPacketsReceived)
}

// TestCInteropCClientConnectsToGoServer connects the C client to this
// implementation's server: the server must decrypt a connect token generated
// by the C implementation with libsodium, and complete the handshake and
// payload exchange with the C client.
func TestCInteropCClientConnectsToGoServer(t *testing.T) {
	clientBinary := cInteropBinary(t, "client")

	serverAddress := "127.0.0.1:40200"

	serverConfig := &ServerConfig{
		ProtocolID: testProtocolID,
		PrivateKey: testPrivateKey,
	}

	server, err := NewServer(serverAddress, serverConfig, 0.0)
	check(t, err == nil)
	defer server.Close()

	server.Start(MaxClients)

	startCBinary(t, clientBinary, serverAddress)

	payload := cInteropPayload()
	payloadPacketsReceived := 0

	start := time.Now()
	deadline := start.Add(cInteropTimeout)

	for time.Now().Before(deadline) {
		currentTime := time.Since(start).Seconds()

		server.Update(currentTime)

		if server.ClientConnected(0) {
			server.SendPacket(0, payload)
		}

		for {
			packet, _ := server.ReceivePacket(0)
			if packet == nil {
				break
			}
			check(t, bytes.Equal(packet, payload))
			payloadPacketsReceived++
		}

		if server.ClientConnected(0) && payloadPacketsReceived >= 10 {
			return // success: the C client connected and exchanged payload packets
		}

		time.Sleep(time.Second / 60)
	}

	t.Fatalf("timed out: %d clients connected, %d payload packets received from C client",
		server.NumConnectedClients(), payloadPacketsReceived)
}
