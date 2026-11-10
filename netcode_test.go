package netcode

import (
	"bytes"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This test suite is a port of the test suite in the C reference implementation.

const (
	testProtocolID         = 0x1122334455667788
	testClientID           = 0x1
	testServerPort         = 40000
	testConnectTokenExpiry = 30
	testTimeoutSeconds     = 15

	// testNowUnix is the fixed Unix time used by the unit tests, so token
	// timestamps do not depend on the wall clock.
	testNowUnix = uint64(1700000000)
)

// TestMain pins the clock for the unit tests. The C interoperability tests run
// the reference implementation in another process with the real clock, so
// leave the clock alone when they are enabled.
func TestMain(m *testing.M) {
	previousNowUnix := nowUnix
	if os.Getenv("NETCODE_C_BIN_DIR") == "" {
		nowUnix = func() uint64 { return testNowUnix }
	}
	code := m.Run()
	nowUnix = previousNowUnix
	os.Exit(code)
}

var testPrivateKey = [KeyBytes]byte{
	0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
	0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
	0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
	0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1,
}

func check(t *testing.T, condition bool) {
	t.Helper()
	if !condition {
		t.Fatal("check failed")
	}
}

func testSendPacketOverride(to *Address, packetData []byte) {}

func testReceivePacketOverride() (packetData []byte, from Address, ok bool) {
	return nil, Address{}, false
}

func requireFunctional(t *testing.T) {
	t.Helper()
	if os.Getenv("NETCODE_FUNCTIONAL_TESTS") != "1" {
		t.Skip("set NETCODE_FUNCTIONAL_TESTS=1 to run tests that use real sockets")
	}
}

func TestQueue(t *testing.T) {
	var queue packetQueue

	check(t, queue.numPackets == 0)
	check(t, queue.startIndex == 0)

	// attempting to pop a packet off an empty queue should return nil

	popped, _ := queue.pop()
	check(t, popped == nil)

	// add some packets to the queue and make sure they pop off in the correct order
	{
		const numPackets = 100

		var packets [numPackets]*connectionPayload

		for i := 0; i < numPackets; i++ {
			packets[i] = &connectionPayload{payloadData: make([]byte, (i+1)*256)}
			check(t, queue.push(packets[i], uint64(i)))
		}

		check(t, queue.numPackets == numPackets)

		for i := 0; i < numPackets; i++ {
			packet, sequence := queue.pop()
			check(t, sequence == uint64(i))
			check(t, packet == packets[i])
		}
	}

	// after all entries are popped off, the queue is empty, so calls to pop should return nil

	check(t, queue.numPackets == 0)

	popped, _ = queue.pop()
	check(t, popped == nil)

	// test that the packet queue can be filled to max capacity

	var packets [packetQueueSize]*connectionPayload

	for i := 0; i < packetQueueSize; i++ {
		packets[i] = &connectionPayload{}
		check(t, queue.push(packets[i], uint64(i)))
	}

	check(t, queue.numPackets == packetQueueSize)

	// when the queue is full, attempting to push a packet should fail

	check(t, !queue.push(&connectionPayload{}, 0))

	// make sure all packets pop off in the correct order

	for i := 0; i < packetQueueSize; i++ {
		packet, sequence := queue.pop()
		check(t, sequence == uint64(i))
		check(t, packet == packets[i])
	}

	// add some packets again

	for i := 0; i < packetQueueSize; i++ {
		check(t, queue.push(packets[i], uint64(i)))
	}

	// clear the queue and make sure that all packets are freed

	queue.clear()

	check(t, queue.startIndex == 0)
	check(t, queue.numPackets == 0)
	for i := 0; i < packetQueueSize; i++ {
		check(t, queue.packets[i] == nil)
	}
}

func TestSequence(t *testing.T) {
	check(t, sequenceNumberBytesRequired(0) == 1)
	check(t, sequenceNumberBytesRequired(0x11) == 1)
	check(t, sequenceNumberBytesRequired(0x1122) == 2)
	check(t, sequenceNumberBytesRequired(0x112233) == 3)
	check(t, sequenceNumberBytesRequired(0x11223344) == 4)
	check(t, sequenceNumberBytesRequired(0x1122334455) == 5)
	check(t, sequenceNumberBytesRequired(0x112233445566) == 6)
	check(t, sequenceNumberBytesRequired(0x11223344556677) == 7)
	check(t, sequenceNumberBytesRequired(0x1122334455667788) == 8)
}

func TestAddress(t *testing.T) {
	{
		badAddresses := []string{
			"",
			"[",
			"[]",
			"[]:",
			":",
			"1",
			"12",
			"123",
			"1234",
			"1234.0.12313.0000",
			"1234.0.12313.0000.0.0.0.0.0",
			"1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131",
			".",
			"..",
			"...",
			"....",
			".....",
			"[::1]]:80",
			"[[::1]]",
			"[::1]:80]",
			"fe80::1%en0",
			"[fe80::1%en0]",
			"[fe80::1%en0]:40000",
		}
		for _, s := range badAddresses {
			if _, err := ParseAddress(s); err == nil {
				t.Fatalf("expected parse error for %q", s)
			}
		}
	}

	// ports must be all digits in [0,65535]. out of range and non-numeric ports must not silently truncate

	{
		address, err := ParseAddress("127.0.0.1:65535")
		check(t, err == nil)
		check(t, address.Type == AddressIPv4)
		check(t, address.Port == 65535)

		address, err = ParseAddress("[::1]:65535")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 65535)

		badPorts := []string{
			"127.0.0.1:65536",
			"127.0.0.1:99999",
			"127.0.0.1:",
			"127.0.0.1:40k",
			"[::1]:65536",
			"[::1]:",
			"[::1]:40k",
		}
		for _, s := range badPorts {
			if _, err := ParseAddress(s); err == nil {
				t.Fatalf("expected parse error for %q", s)
			}
		}
	}

	{
		address, err := ParseAddress("107.77.207.77")
		check(t, err == nil)
		check(t, address.Type == AddressIPv4)
		check(t, address.Port == 0)
		check(t, address.IPv4 == [4]byte{107, 77, 207, 77})
	}

	{
		address, err := ParseAddress("127.0.0.1")
		check(t, err == nil)
		check(t, address.Type == AddressIPv4)
		check(t, address.Port == 0)
		check(t, address.IPv4 == [4]byte{127, 0, 0, 1})
	}

	{
		address, err := ParseAddress("107.77.207.77:40000")
		check(t, err == nil)
		check(t, address.Type == AddressIPv4)
		check(t, address.Port == 40000)
		check(t, address.IPv4 == [4]byte{107, 77, 207, 77})
	}

	{
		address, err := ParseAddress("127.0.0.1:40000")
		check(t, err == nil)
		check(t, address.Type == AddressIPv4)
		check(t, address.Port == 40000)
		check(t, address.IPv4 == [4]byte{127, 0, 0, 1})
	}

	{
		address, err := ParseAddress("fe80::202:b3ff:fe1e:8329")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{0xfe80, 0, 0, 0, 0x0202, 0xb3ff, 0xfe1e, 0x8329})
	}

	{
		address, err := ParseAddress("::")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{})
	}

	{
		address, err := ParseAddress("::1")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{0, 0, 0, 0, 0, 0, 0, 1})
	}

	{
		address, err := ParseAddress("::0")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{})
	}

	{
		address, err := ParseAddress("[::1]")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{0, 0, 0, 0, 0, 0, 0, 1})
	}

	{
		address, err := ParseAddress("[::0]")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{})
	}

	{
		address, err := ParseAddress("[fe80::1]")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 0)
		check(t, address.IPv6 == [8]uint16{0xfe80, 0, 0, 0, 0, 0, 0, 1})
	}

	{
		address, err := ParseAddress("[fe80::202:b3ff:fe1e:8329]:40000")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 40000)
		check(t, address.IPv6 == [8]uint16{0xfe80, 0, 0, 0, 0x0202, 0xb3ff, 0xfe1e, 0x8329})
	}

	{
		address, err := ParseAddress("[::]:40000")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 40000)
		check(t, address.IPv6 == [8]uint16{})
	}

	{
		address, err := ParseAddress("[::1]:5")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 5)
		check(t, address.IPv6 == [8]uint16{0, 0, 0, 0, 0, 0, 0, 1})
	}

	{
		address, err := ParseAddress("[fe80::1]:5")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 5)
		check(t, address.IPv6 == [8]uint16{0xfe80, 0, 0, 0, 0, 0, 0, 1})
	}

	{
		address, err := ParseAddress("[::1]:40000")
		check(t, err == nil)
		check(t, address.Type == AddressIPv6)
		check(t, address.Port == 40000)
		check(t, address.IPv6 == [8]uint16{0, 0, 0, 0, 0, 0, 0, 1})
	}

	// addresses format back to strings that parse to the same address

	{
		roundTrips := []string{
			"107.77.207.77",
			"127.0.0.1:40000",
			"[::1]:40000",
			"fe80::202:b3ff:fe1e:8329",
		}
		for _, s := range roundTrips {
			address, err := ParseAddress(s)
			check(t, err == nil)
			parsed, err := ParseAddress(address.String())
			check(t, err == nil)
			check(t, address.Equal(parsed))
		}
		check(t, Address{}.String() == "NONE")
	}

	// addresses of type none are never equal to anything, including each other

	{
		var a, b Address
		check(t, !a.Equal(b))
	}
}

func testServerAddress() Address {
	return Address{
		Type: AddressIPv4,
		IPv4: [4]byte{127, 0, 0, 1},
		Port: testServerPort,
	}
}

func TestConnectToken(t *testing.T) {
	// generate a connect token

	serverAddress := testServerAddress()

	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)

	inputToken := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{serverAddress}, userData)

	check(t, inputToken.clientID == testClientID)
	check(t, inputToken.numServerAddresses == 1)
	check(t, bytes.Equal(inputToken.userData[:], userData))
	check(t, inputToken.serverAddresses[0].Equal(serverAddress))

	// write it to a buffer

	var buffer [connectTokenPrivateBytes]byte
	inputToken.write(buffer[:])

	// encrypt the buffer

	expireTimestamp := testNowUnix + 30
	nonce := generateNonce()
	key := GenerateKey()

	check(t, encryptConnectTokenPrivate(buffer[:], testProtocolID, expireTimestamp, nonce[:], key) == nil)

	// decrypt the buffer

	check(t, decryptConnectTokenPrivate(buffer[:], testProtocolID, expireTimestamp, nonce[:], key) == nil)

	// read the connect token back in

	var outputToken connectTokenPrivate
	check(t, outputToken.read(buffer[:]) == nil)

	// make sure that everything matches the original connect token

	check(t, outputToken.clientID == inputToken.clientID)
	check(t, outputToken.timeoutSeconds == inputToken.timeoutSeconds)
	check(t, outputToken.numServerAddresses == inputToken.numServerAddresses)
	check(t, outputToken.serverAddresses[0].Equal(inputToken.serverAddresses[0]))
	check(t, outputToken.clientToServerKey == inputToken.clientToServerKey)
	check(t, outputToken.serverToClientKey == inputToken.serverToClientKey)
	check(t, outputToken.userData == inputToken.userData)
}

func TestChallengeToken(t *testing.T) {
	// generate a challenge token

	var inputToken challengeToken
	inputToken.clientID = testClientID
	RandomBytes(inputToken.userData[:])

	// write it to a buffer

	var buffer [challengeTokenBytes]byte
	inputToken.write(buffer[:])

	// encrypt the buffer

	sequence := uint64(1000)
	key := GenerateKey()

	check(t, encryptChallengeToken(buffer[:], sequence, key) == nil)

	// decrypt the buffer

	check(t, decryptChallengeToken(buffer[:], sequence, key) == nil)

	// read the challenge token back in

	var outputToken challengeToken
	check(t, outputToken.read(buffer[:]) == nil)

	// make sure that everything matches the original challenge token

	check(t, outputToken.clientID == inputToken.clientID)
	check(t, outputToken.userData == inputToken.userData)
}

func allPacketsAllowed() [connectionNumPackets]bool {
	var allowed [connectionNumPackets]bool
	for i := range allowed {
		allowed[i] = true
	}
	return allowed
}

func TestConnectionRequestPacket(t *testing.T) {
	// generate a connect token

	serverAddress := testServerAddress()

	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)

	inputToken := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{serverAddress}, userData)

	check(t, inputToken.clientID == testClientID)
	check(t, inputToken.numServerAddresses == 1)
	check(t, bytes.Equal(inputToken.userData[:], userData))
	check(t, inputToken.serverAddresses[0].Equal(serverAddress))

	// write the connect token to a buffer (non-encrypted)

	var connectTokenData [connectTokenPrivateBytes]byte
	inputToken.write(connectTokenData[:])

	// copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

	encryptedConnectTokenData := connectTokenData

	connectTokenExpireTimestamp := testNowUnix + 30
	connectTokenNonce := generateNonce()
	connectTokenKey := GenerateKey()

	check(t, encryptConnectTokenPrivate(encryptedConnectTokenData[:], testProtocolID, connectTokenExpireTimestamp, connectTokenNonce[:], connectTokenKey) == nil)

	// setup a connection request packet wrapping the encrypted connect token

	inputPacket := &connectionRequest{
		versionInfo:                 versionInfo,
		protocolID:                  testProtocolID,
		connectTokenExpireTimestamp: connectTokenExpireTimestamp,
		connectTokenNonce:           connectTokenNonce,
		connectTokenData:            encryptedConnectTokenData,
	}

	// write the connection request packet to a buffer

	var buffer [2048]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, connectTokenKey, &allowedPackets, nil).(*connectionRequest)

	check(t, ok)

	// make sure the read packet matches what was written

	check(t, outputPacket.versionInfo == inputPacket.versionInfo)
	check(t, outputPacket.protocolID == inputPacket.protocolID)
	check(t, outputPacket.connectTokenExpireTimestamp == inputPacket.connectTokenExpireTimestamp)
	check(t, outputPacket.connectTokenNonce == inputPacket.connectTokenNonce)
	check(t, bytes.Equal(outputPacket.connectTokenData[:connectTokenPrivateBytes-MacBytes], connectTokenData[:connectTokenPrivateBytes-MacBytes]))
}

func TestConnectionDeniedPacket(t *testing.T) {
	// setup a connection denied packet

	inputPacket := &connectionDenied{}

	// write the packet to a buffer

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the packet back in from the buffer

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, nil).(*connectionDenied)

	check(t, ok)
	check(t, outputPacket != nil)
	check(t, sequence == 1000)
}

func TestConnectionChallengePacket(t *testing.T) {
	// setup a connection challenge packet

	inputPacket := &connectionChallenge{}
	inputPacket.challengeTokenSequence = 0
	RandomBytes(inputPacket.challengeTokenData[:])

	// write the packet to a buffer

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the packet back in from the buffer

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, nil).(*connectionChallenge)

	check(t, ok)

	// make sure the read packet matches what was written

	check(t, outputPacket.challengeTokenSequence == inputPacket.challengeTokenSequence)
	check(t, outputPacket.challengeTokenData == inputPacket.challengeTokenData)
}

func TestConnectionResponsePacket(t *testing.T) {
	// setup a connection response packet

	inputPacket := &connectionResponse{}
	inputPacket.challengeTokenSequence = 0
	RandomBytes(inputPacket.challengeTokenData[:])

	// write the packet to a buffer

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the packet back in from the buffer

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, nil).(*connectionResponse)

	check(t, ok)

	// make sure the read packet matches what was written

	check(t, outputPacket.challengeTokenSequence == inputPacket.challengeTokenSequence)
	check(t, outputPacket.challengeTokenData == inputPacket.challengeTokenData)
}

func TestConnectionKeepAlivePacket(t *testing.T) {
	// setup a connection keep alive packet

	inputPacket := &connectionKeepAlive{
		clientIndex: 10,
		maxClients:  16,
	}

	// write the packet to a buffer

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the packet back in from the buffer

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, nil).(*connectionKeepAlive)

	check(t, ok)

	// make sure the read packet matches what was written

	check(t, outputPacket.clientIndex == inputPacket.clientIndex)
	check(t, outputPacket.maxClients == inputPacket.maxClients)
}

func TestConnectionPayloadPacket(t *testing.T) {
	// setup a connection payload packet

	inputPacket := &connectionPayload{payloadData: make([]byte, maxPayloadBytes)}
	RandomBytes(inputPacket.payloadData)

	// write the packet to a buffer

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the packet back in from the buffer

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, nil).(*connectionPayload)

	check(t, ok)

	// make sure the read packet matches what was written

	check(t, bytes.Equal(outputPacket.payloadData, inputPacket.payloadData))
}

func TestConnectionDisconnectPacket(t *testing.T) {
	// setup a connection disconnect packet

	inputPacket := &connectionDisconnect{}

	// write the packet to a buffer

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	// read the packet back in from the buffer

	var sequence uint64
	allowedPackets := allPacketsAllowed()

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, nil).(*connectionDisconnect)

	check(t, ok)
	check(t, outputPacket != nil)
}

func TestReadPacketRejectsInvalidPackets(t *testing.T) {
	packetKey := GenerateKey()
	wrongPacketKey := GenerateKey()
	privateKey := GenerateKey()
	wrongPrivateKey := GenerateKey()

	connectTokenExpireTimestamp := testNowUnix + 30
	connectTokenNonce := generateNonce()
	var connectTokenData [connectTokenPrivateBytes]byte
	check(t, encryptConnectTokenPrivate(connectTokenData[:], testProtocolID, connectTokenExpireTimestamp, connectTokenNonce[:], privateKey) == nil)

	testCases := []struct {
		name     string
		packet   packet
		private  []byte
		wrongKey []byte
	}{
		{
			name: "connection request",
			packet: &connectionRequest{
				versionInfo:                 versionInfo,
				protocolID:                  testProtocolID,
				connectTokenExpireTimestamp: connectTokenExpireTimestamp,
				connectTokenNonce:           connectTokenNonce,
				connectTokenData:            connectTokenData,
			},
			private:  privateKey,
			wrongKey: wrongPrivateKey,
		},
		{
			name:     "connection denied",
			packet:   &connectionDenied{},
			wrongKey: wrongPacketKey,
		},
		{
			name:     "connection challenge",
			packet:   &connectionChallenge{challengeTokenSequence: 1000},
			wrongKey: wrongPacketKey,
		},
		{
			name:     "connection response",
			packet:   &connectionResponse{challengeTokenSequence: 1000},
			wrongKey: wrongPacketKey,
		},
		{
			name:     "connection keep alive",
			packet:   &connectionKeepAlive{clientIndex: 10, maxClients: 16},
			wrongKey: wrongPacketKey,
		},
		{
			name:     "connection payload",
			packet:   &connectionPayload{payloadData: []byte("payload")},
			wrongKey: wrongPacketKey,
		},
		{
			name:     "connection disconnect",
			packet:   &connectionDisconnect{},
			wrongKey: wrongPacketKey,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var buffer [maxPacketBytes]byte
			bytesWritten := writePacket(testCase.packet, buffer[:], 1000, packetKey, testProtocolID)
			check(t, bytesWritten > 0)

			allowedPackets := allPacketsAllowed()

			read := func(data []byte, key []byte, protocolID uint64, privateKey []byte) packet {
				copied := append([]byte(nil), data...)
				var sequence uint64
				return readPacket(copied, &sequence, key, protocolID, testNowUnix, 0, privateKey, &allowedPackets, nil)
			}

			// the unmodified packet is accepted

			check(t, read(buffer[:bytesWritten], packetKey, testProtocolID, testCase.private) != nil)

			// a flipped ciphertext or tag byte is refused

			tampered := append([]byte(nil), buffer[:bytesWritten]...)
			tampered[bytesWritten-1] ^= 0xFF
			check(t, read(tampered, packetKey, testProtocolID, testCase.private) == nil)

			// a wrong key is refused

			if testCase.private != nil {
				// a connection request is decrypted with the private key
				check(t, read(buffer[:bytesWritten], packetKey, testProtocolID, testCase.wrongKey) == nil)
			} else {
				check(t, read(buffer[:bytesWritten], testCase.wrongKey, testProtocolID, nil) == nil)
			}

			// a wrong protocol id is refused

			check(t, read(buffer[:bytesWritten], packetKey, testProtocolID+1, testCase.private) == nil)
		})
	}
}

func TestConnectTokenPublic(t *testing.T) {
	// generate a private connect token

	serverAddress := testServerAddress()

	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)

	connectTokenPrivateStruct := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{serverAddress}, userData)

	check(t, connectTokenPrivateStruct.clientID == testClientID)
	check(t, connectTokenPrivateStruct.numServerAddresses == 1)
	check(t, bytes.Equal(connectTokenPrivateStruct.userData[:], userData))
	check(t, connectTokenPrivateStruct.serverAddresses[0].Equal(serverAddress))

	// write it to a buffer

	var connectTokenPrivateData [connectTokenPrivateBytes]byte
	connectTokenPrivateStruct.write(connectTokenPrivateData[:])

	// encrypt the buffer

	createTimestamp := testNowUnix
	expireTimestamp := createTimestamp + 30
	connectTokenNonce := generateNonce()
	key := GenerateKey()
	check(t, encryptConnectTokenPrivate(connectTokenPrivateData[:], testProtocolID, expireTimestamp, connectTokenNonce[:], key) == nil)

	// wrap a public connect token around the private connect token data

	var inputConnectToken connectToken
	inputConnectToken.protocolID = testProtocolID
	inputConnectToken.createTimestamp = createTimestamp
	inputConnectToken.expireTimestamp = expireTimestamp
	inputConnectToken.nonce = connectTokenNonce
	inputConnectToken.privateData = connectTokenPrivateData
	inputConnectToken.numServerAddresses = 1
	inputConnectToken.serverAddresses[0] = serverAddress
	inputConnectToken.clientToServerKey = connectTokenPrivateStruct.clientToServerKey
	inputConnectToken.serverToClientKey = connectTokenPrivateStruct.serverToClientKey
	inputConnectToken.timeoutSeconds = testTimeoutSeconds

	// write the connect token to a buffer

	var buffer [ConnectTokenBytes]byte
	inputConnectToken.write(buffer[:])

	// read the buffer back in

	var outputConnectToken connectToken
	check(t, outputConnectToken.read(buffer[:]) == nil)

	// make sure the public connect token matches what was written

	check(t, outputConnectToken.protocolID == inputConnectToken.protocolID)
	check(t, outputConnectToken.createTimestamp == inputConnectToken.createTimestamp)
	check(t, outputConnectToken.expireTimestamp == inputConnectToken.expireTimestamp)
	check(t, outputConnectToken.nonce == inputConnectToken.nonce)
	check(t, outputConnectToken.privateData == inputConnectToken.privateData)
	check(t, outputConnectToken.numServerAddresses == inputConnectToken.numServerAddresses)
	check(t, outputConnectToken.serverAddresses[0].Equal(inputConnectToken.serverAddresses[0]))
	check(t, outputConnectToken.clientToServerKey == inputConnectToken.clientToServerKey)
	check(t, outputConnectToken.serverToClientKey == inputConnectToken.serverToClientKey)
	check(t, outputConnectToken.timeoutSeconds == inputConnectToken.timeoutSeconds)
}

func TestGenerateConnectTokenUsesInjectedClock(t *testing.T) {
	const injectedNow = uint64(1234567890)

	previousNowUnix := nowUnix
	nowUnix = func() uint64 { return injectedNow }
	defer func() { nowUnix = previousNowUnix }()

	serverAddress := testServerAddress()

	connectTokenData, err := GenerateConnectToken(
		[]string{serverAddress.String()},
		[]string{serverAddress.String()},
		testConnectTokenExpiry,
		testTimeoutSeconds,
		testClientID,
		testProtocolID,
		testPrivateKey[:],
		nil,
	)
	check(t, err == nil)

	var token connectToken
	check(t, token.read(connectTokenData) == nil)
	check(t, token.createTimestamp == injectedNow)
	check(t, token.expireTimestamp == injectedNow+testConnectTokenExpiry)
}

func TestGenerateConnectTokenRejectsOutOfRangeTimeout(t *testing.T) {
	serverAddress := testServerAddress()

	for _, timeoutSeconds := range []int{math.MaxInt32 + 1, math.MinInt32 - 1} {
		_, err := GenerateConnectToken(
			[]string{serverAddress.String()},
			[]string{serverAddress.String()},
			testConnectTokenExpiry,
			timeoutSeconds,
			testClientID,
			testProtocolID,
			testPrivateKey[:],
			nil,
		)
		check(t, err != nil)
	}
}

func TestEncryptionManager(t *testing.T) {
	var manager encryptionManager
	manager.reset()

	currentTime := 100.0

	// generate some test encryption mappings

	type encryptionMapping struct {
		address    Address
		sendKey    []byte
		receiveKey []byte
	}

	const numEncryptionMappings = 5

	var mappings [numEncryptionMappings]encryptionMapping
	for i := 0; i < numEncryptionMappings; i++ {
		mappings[i].address = Address{Type: AddressIPv6, IPv6: [8]uint16{0, 0, 0, 0, 0, 0, 0, 1}, Port: uint16(20000 + i)}
		mappings[i].sendKey = GenerateKey()
		mappings[i].receiveKey = GenerateKey()
	}

	// add the encryption mappings to the manager and make sure they can be looked up by address

	for i := 0; i < numEncryptionMappings; i++ {
		encryptionIndex := manager.findEncryptionMapping(&mappings[i].address, currentTime)

		check(t, encryptionIndex == -1)

		check(t, manager.getSendKey(encryptionIndex) == nil)
		check(t, manager.getReceiveKey(encryptionIndex) == nil)

		check(t, manager.addEncryptionMapping(&mappings[i].address, mappings[i].sendKey, mappings[i].receiveKey, currentTime, -1.0, testTimeoutSeconds, -1))

		encryptionIndex = manager.findEncryptionMapping(&mappings[i].address, currentTime)

		sendKey := manager.getSendKey(encryptionIndex)
		receiveKey := manager.getReceiveKey(encryptionIndex)

		check(t, sendKey != nil)
		check(t, receiveKey != nil)

		check(t, bytes.Equal(sendKey, mappings[i].sendKey))
		check(t, bytes.Equal(receiveKey, mappings[i].receiveKey))
	}

	// removing an encryption mapping that doesn't exist should return false
	{
		address := Address{Type: AddressIPv6, IPv6: [8]uint16{0, 0, 0, 0, 0, 0, 0, 1}, Port: 50000}
		check(t, !manager.removeEncryptionMapping(&address, currentTime))
	}

	// remove the first and last encryption mappings

	check(t, manager.removeEncryptionMapping(&mappings[0].address, currentTime))
	check(t, manager.removeEncryptionMapping(&mappings[numEncryptionMappings-1].address, currentTime))

	// make sure the encryption mappings that were removed can no longer be looked up by address

	for i := 0; i < numEncryptionMappings; i++ {
		encryptionIndex := manager.findEncryptionMapping(&mappings[i].address, currentTime)

		sendKey := manager.getSendKey(encryptionIndex)
		receiveKey := manager.getReceiveKey(encryptionIndex)

		if i != 0 && i != numEncryptionMappings-1 {
			check(t, sendKey != nil)
			check(t, receiveKey != nil)
			check(t, bytes.Equal(sendKey, mappings[i].sendKey))
			check(t, bytes.Equal(receiveKey, mappings[i].receiveKey))
		} else {
			check(t, sendKey == nil)
			check(t, receiveKey == nil)
		}
	}

	// add the encryption mappings back in

	check(t, manager.addEncryptionMapping(&mappings[0].address, mappings[0].sendKey, mappings[0].receiveKey, currentTime, -1.0, testTimeoutSeconds, -1))
	check(t, manager.addEncryptionMapping(&mappings[numEncryptionMappings-1].address, mappings[numEncryptionMappings-1].sendKey, mappings[numEncryptionMappings-1].receiveKey, currentTime, -1.0, testTimeoutSeconds, -1))

	// all encryption mappings should be able to be looked up by address again

	for i := 0; i < numEncryptionMappings; i++ {
		encryptionIndex := manager.findEncryptionMapping(&mappings[i].address, currentTime)

		sendKey := manager.getSendKey(encryptionIndex)
		receiveKey := manager.getReceiveKey(encryptionIndex)

		check(t, sendKey != nil)
		check(t, receiveKey != nil)
		check(t, bytes.Equal(sendKey, mappings[i].sendKey))
		check(t, bytes.Equal(receiveKey, mappings[i].receiveKey))
	}

	// check that encryption mappings time out properly

	currentTime += testTimeoutSeconds * 2

	for i := 0; i < numEncryptionMappings; i++ {
		encryptionIndex := manager.findEncryptionMapping(&mappings[i].address, currentTime)

		sendKey := manager.getSendKey(encryptionIndex)
		receiveKey := manager.getReceiveKey(encryptionIndex)

		check(t, sendKey == nil)
		check(t, receiveKey == nil)
	}

	// add the same encryption mappings after timeout

	for i := 0; i < numEncryptionMappings; i++ {
		encryptionIndex := manager.findEncryptionMapping(&mappings[i].address, currentTime)

		check(t, encryptionIndex == -1)

		check(t, manager.getSendKey(encryptionIndex) == nil)
		check(t, manager.getReceiveKey(encryptionIndex) == nil)

		check(t, manager.addEncryptionMapping(&mappings[i].address, mappings[i].sendKey, mappings[i].receiveKey, currentTime, -1.0, testTimeoutSeconds, -1))

		encryptionIndex = manager.findEncryptionMapping(&mappings[i].address, currentTime)

		sendKey := manager.getSendKey(encryptionIndex)
		receiveKey := manager.getReceiveKey(encryptionIndex)

		check(t, sendKey != nil)
		check(t, receiveKey != nil)
		check(t, bytes.Equal(sendKey, mappings[i].sendKey))
		check(t, bytes.Equal(receiveKey, mappings[i].receiveKey))
	}

	// reset the encryption manager and verify that all encryption mappings have been removed

	manager.reset()

	for i := 0; i < numEncryptionMappings; i++ {
		encryptionIndex := manager.findEncryptionMapping(&mappings[i].address, currentTime)

		check(t, manager.getSendKey(encryptionIndex) == nil)
		check(t, manager.getReceiveKey(encryptionIndex) == nil)
	}

	// test the expire time for encryption mapping works as expected

	check(t, manager.addEncryptionMapping(&mappings[0].address, mappings[0].sendKey, mappings[0].receiveKey, currentTime, currentTime+1.0, testTimeoutSeconds, -1))

	encryptionIndex := manager.findEncryptionMapping(&mappings[0].address, currentTime)

	check(t, encryptionIndex != -1)

	check(t, manager.findEncryptionMapping(&mappings[0].address, currentTime+1.1) == -1)

	manager.setExpireTime(encryptionIndex, -1.0)

	check(t, manager.findEncryptionMapping(&mappings[0].address, currentTime) == encryptionIndex)
}

func TestReplayProtection(t *testing.T) {
	var replay replayProtection

	for i := 0; i < 2; i++ {
		replay.reset()

		check(t, replay.mostRecentSequence == 0)

		// the first time we receive packets, they should not be already received

		const maxSequence = replayProtectionBufferSize * 4

		for sequence := uint64(0); sequence < maxSequence; sequence++ {
			check(t, !replay.alreadyReceived(sequence))
			replay.advanceSequence(sequence)
		}

		// old packets outside buffer should be considered already received

		check(t, replay.alreadyReceived(0))

		// packets received a second time should be flagged already received

		for sequence := uint64(maxSequence - 10); sequence < maxSequence; sequence++ {
			check(t, replay.alreadyReceived(sequence))
		}

		// jumping ahead to a much higher sequence should be considered not already received

		check(t, !replay.alreadyReceived(maxSequence+replayProtectionBufferSize))

		// old packets should be considered already received

		for sequence := uint64(0); sequence < maxSequence; sequence++ {
			check(t, replay.alreadyReceived(sequence))
		}
	}

	// sequence numbers near the top of the sequence space must not be falsely rejected
	// as replays. "sequence + buffer size" overflowed in the already received check and
	// treated the top of the sequence space as ancient packets.

	replay.reset()

	const maxUint64 = uint64(0xFFFFFFFFFFFFFFFF)

	check(t, !replay.alreadyReceived(maxUint64-replayProtectionBufferSize))
	replay.advanceSequence(maxUint64 - replayProtectionBufferSize)

	check(t, !replay.alreadyReceived(maxUint64-1))
	replay.advanceSequence(maxUint64 - 1)

	// and a replayed packet up there is still caught

	check(t, replay.alreadyReceived(maxUint64-1))

	// while packets that fell out of the window are rejected as before

	check(t, replay.alreadyReceived(maxUint64-1-replayProtectionBufferSize))

	// max uint64 is the replay buffer's empty-slot marker, so it is not a valid
	// received sequence. It must be refused, must never update the most recent
	// sequence, and must not push otherwise valid sequences out of the window.

	replay.reset()

	check(t, !replay.alreadyReceived(maxUint64-1))
	replay.advanceSequence(maxUint64 - 1)

	check(t, replay.alreadyReceived(maxUint64))
	replay.advanceSequence(maxUint64)

	check(t, replay.mostRecentSequence == maxUint64-1)
	check(t, replay.alreadyReceived(maxUint64))
	check(t, !replay.alreadyReceived(maxUint64-2))

	// the same sequence must be refused when it arrives in a keep alive packet,
	// even without replay protection, leaving the window unchanged.

	packetKey := GenerateKey()
	var buffer [maxPacketBytes]byte
	bytesWritten := writePacket(&connectionKeepAlive{}, buffer[:], maxUint64, packetKey, testProtocolID)
	check(t, bytesWritten > 0)

	allowedPackets := allPacketsAllowed()

	var sequence uint64
	check(t, readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID,
		uint64(time.Now().Unix()), 0, nil, &allowedPackets, nil) == nil)

	check(t, readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID,
		uint64(time.Now().Unix()), 0, nil, &allowedPackets, &replay) == nil)
	check(t, replay.mostRecentSequence == maxUint64-1)
	check(t, !replay.alreadyReceived(maxUint64-2))

	// a normal sequence still arrives after the reserved one was refused, and a
	// replay of that normal packet is still caught

	replay.reset()

	// refusing the reserved sequence at the start of the window must leave the
	// most recent sequence at zero, so the next normal packet is still accepted

	bytesWritten = writePacket(&connectionKeepAlive{}, buffer[:], maxUint64, packetKey, testProtocolID)
	check(t, bytesWritten > 0)

	check(t, readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID,
		uint64(time.Now().Unix()), 0, nil, &allowedPackets, &replay) == nil)
	check(t, replay.mostRecentSequence == 0)

	bytesWritten = writePacket(&connectionKeepAlive{}, buffer[:], 1, packetKey, testProtocolID)
	check(t, bytesWritten > 0)

	check(t, readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID,
		uint64(time.Now().Unix()), 0, nil, &allowedPackets, &replay) != nil)
	check(t, sequence == 1)
	check(t, replay.mostRecentSequence == 1)
	check(t, replay.alreadyReceived(1))

	check(t, readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID,
		uint64(time.Now().Unix()), 0, nil, &allowedPackets, &replay) == nil)
}

func TestReadPacketRejectsReplay(t *testing.T) {
	inputPacket := &connectionPayload{payloadData: []byte("replay test payload")}

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	wireBytes := make([]byte, bytesWritten)
	copy(wireBytes, buffer[:bytesWritten])

	var replay replayProtection
	replay.reset()

	allowedPackets := allPacketsAllowed()

	// readPacket decrypts in place, so each call gets its own copy of the same wire bytes

	firstBytes := make([]byte, len(wireBytes))
	copy(firstBytes, wireBytes)

	var firstSequence uint64
	firstPacket := readPacket(firstBytes, &firstSequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, &replay)

	check(t, firstPacket != nil)
	check(t, firstSequence == 1000)

	secondBytes := make([]byte, len(wireBytes))
	copy(secondBytes, wireBytes)

	var secondSequence uint64
	secondPacket := readPacket(secondBytes, &secondSequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, &replay)

	check(t, secondPacket == nil)
}

func TestReadPacketIgnoresCorruptedPacket(t *testing.T) {
	inputPacket := &connectionPayload{payloadData: []byte("corrupted packet payload")}

	var buffer [maxPacketBytes]byte
	packetKey := GenerateKey()

	bytesWritten := writePacket(inputPacket, buffer[:], 1000, packetKey, testProtocolID)

	check(t, bytesWritten > 0)

	wireBytes := make([]byte, bytesWritten)
	copy(wireBytes, buffer[:bytesWritten])

	var replay replayProtection
	replay.reset()

	allowedPackets := allPacketsAllowed()

	// a corrupted packet at sequence 1000 must be ignored without affecting replay protection

	corruptedBytes := make([]byte, len(wireBytes))
	copy(corruptedBytes, wireBytes)
	corruptedBytes[len(corruptedBytes)-1] ^= 0xFF

	var corruptedSequence uint64
	corruptedPacket := readPacket(corruptedBytes, &corruptedSequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, &replay)

	check(t, corruptedPacket == nil)
	check(t, corruptedSequence == 1000)

	// the authentic packet at the same sequence must still be accepted

	authenticBytes := make([]byte, len(wireBytes))
	copy(authenticBytes, wireBytes)

	var sequence uint64
	outputPacket, ok := readPacket(authenticBytes, &sequence, packetKey, testProtocolID, testNowUnix, 0, nil, &allowedPackets, &replay).(*connectionPayload)

	check(t, ok)
	check(t, sequence == 1000)
	check(t, bytes.Equal(outputPacket.payloadData, inputPacket.payloadData))
}

func TestRuntimeGuards(t *testing.T) {
	// out of range arguments to public entry points must not crash or corrupt state

	// no private key needed: nothing in this test decrypts anything

	serverConfig := &ServerConfig{ProtocolID: testProtocolID, OverrideSendAndReceive: true, SendPacketOverride: testSendPacketOverride, ReceivePacketOverride: testReceivePacketOverride}

	server, err := NewServer("127.0.0.1:40000", serverConfig, 0.0)
	check(t, err == nil)
	defer server.Close()

	// starting with an out of range number of clients must not start the server

	server.Start(0)
	check(t, !server.Running())

	server.Start(-1)
	check(t, !server.Running())

	server.Start(MaxClients + 1)
	check(t, !server.Running())

	server.Start(1)
	check(t, server.Running())
	check(t, server.MaxClients() == 1)

	// out of range client indices must return cleanly. max clients is 1, so 1 is out of range

	check(t, server.ClientUserData(-1) == nil)
	check(t, server.ClientUserData(1) == nil)
	check(t, server.ClientUserData(MaxClients) == nil)

	check(t, server.NextPacketSequence(-1) == 0)
	check(t, server.NextPacketSequence(1) == 0)

	check(t, !server.ClientLoopback(-1))
	check(t, !server.ClientLoopback(1))

	packetData, _ := server.ReceivePacket(-1)
	check(t, packetData == nil)
	packetData, _ = server.ReceivePacket(1)
	check(t, packetData == nil)

	payload := make([]byte, MaxPacketSize)

	server.SendPacket(-1, payload)
	server.SendPacket(1, payload)

	server.DisconnectClient(-1)
	server.DisconnectClient(1)

	server.ConnectLoopbackClient(-1, 1, nil)
	server.ConnectLoopbackClient(1, 1, nil)

	server.DisconnectLoopbackClient(-1)
	server.DisconnectLoopbackClient(1)

	server.ProcessLoopbackPacket(-1, payload, 0)
	server.ProcessLoopbackPacket(1, payload, 0)

	// none of the above may have connected anybody or torn anything down

	check(t, server.Running())
	check(t, server.NumConnectedClients() == 0)
}

func TestConnectLoopbackClientRequiresSendLoopbackPacketCallback(t *testing.T) {
	// a loopback connection needs a send callback, so without one it must be
	// refused rather than accepted in a half-connected state

	serverConfig := &ServerConfig{ProtocolID: testProtocolID, OverrideSendAndReceive: true, SendPacketOverride: testSendPacketOverride, ReceivePacketOverride: testReceivePacketOverride}

	server, err := NewServer("127.0.0.1:40000", serverConfig, 1000.0)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	server.ConnectLoopbackClient(0, testClientID, nil)

	server.SendPacket(0, []byte{1})

	check(t, !server.ClientLoopback(0))
	check(t, !server.ClientConnected(0))
	check(t, server.NumConnectedClients() == 0)
}

func TestConnectLoopbackRequiresSendLoopbackPacketCallback(t *testing.T) {
	// a loopback connection needs a send callback, so without one the client
	// must stay disconnected

	client, err := NewClient("127.0.0.1:50000", &ClientConfig{OverrideSendAndReceive: true, SendPacketOverride: testSendPacketOverride, ReceivePacketOverride: testReceivePacketOverride}, 1000.0)
	check(t, err == nil)
	defer client.Close()

	client.ConnectLoopback(0, 1)

	client.SendPacket([]byte{1})

	check(t, !client.Loopback())
	check(t, client.State() == ClientStateDisconnected)
}

func TestVersionConstants(t *testing.T) {
	check(t, VersionMajor == 1)
	check(t, VersionMinor == 4)
	check(t, VersionPatch == 9)
	check(t, VersionFull == "1.4.9")
}

func TestInitAndDefaults(t *testing.T) {
	requireFunctional(t)
	// a nil config must give working defaults instead of crashing

	{
		client, err := NewClient("127.0.0.1:50000", nil, 0.0)
		check(t, err == nil)
		check(t, client != nil)
		client.Close()
	}

	{
		server, err := NewServer("127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)
		check(t, server != nil)
		server.Close()
	}
}

func TestClientCreateError(t *testing.T) {
	requireFunctional(t)
	// successful create returns no error

	{
		client, err := NewClient("0.0.0.0:50000", nil, 0.0)
		check(t, err == nil)
		check(t, client != nil)
		client.Close()
	}

	// bad first address

	{
		client, err := NewClient("not an address", nil, 0.0)
		check(t, client == nil)
		check(t, errors.Is(err, ErrClientParseAddressFailed))
	}

	// bad second address

	{
		client, err := NewClientDual("0.0.0.0:50000", "not an address", nil, 0.0)
		check(t, client == nil)
		check(t, errors.Is(err, ErrClientParseAddress2Failed))
	}

	// the network simulator requires binding to a specific port

	{
		simulatorConfig := &ClientConfig{NetworkSimulator: NewNetworkSimulator()}

		client, err := NewClient("0.0.0.0", simulatorConfig, 0.0)
		check(t, client == nil)
		check(t, errors.Is(err, ErrClientSimulatorRequiresPort))
	}

	// binding a second client to a port already in use fails at socket creation (ipv4)

	func() {
		firstClient, err := NewClient("127.0.0.1:50000", nil, 0.0)
		check(t, err == nil)
		defer firstClient.Close()

		client, err := NewClient("127.0.0.1:50000", nil, 0.0)
		check(t, client == nil)
		check(t, errors.Is(err, ErrClientCreateSocketIPv4Failed))
	}()

	// and the same over ipv6 reports the ipv6 error

	func() {
		firstClient, err := NewClient("[::1]:50000", nil, 0.0)
		check(t, err == nil)
		defer firstClient.Close()

		client, err := NewClient("[::1]:50000", nil, 0.0)
		check(t, client == nil)
		check(t, errors.Is(err, ErrClientCreateSocketIPv6Failed))
	}()
}

func TestServerCreateError(t *testing.T) {
	requireFunctional(t)
	// successful create returns no error

	{
		server, err := NewServer("127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)
		check(t, server != nil)
		server.Close()
	}

	// bad first address

	{
		server, err := NewServer("not an address", nil, 0.0)
		check(t, server == nil)
		check(t, errors.Is(err, ErrServerParseAddressFailed))
	}

	// bad second address

	{
		server, err := NewServerDual("127.0.0.1:40000", "not an address", nil, 0.0)
		check(t, server == nil)
		check(t, errors.Is(err, ErrServerParseAddress2Failed))
	}

	// a port already in use is reported as a bind failure, distinct from other socket errors (ipv4)

	func() {
		firstServer, err := NewServer("127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)
		defer firstServer.Close()

		server, err := NewServer("127.0.0.1:40000", nil, 0.0)
		check(t, server == nil)
		check(t, errors.Is(err, ErrServerBindSocketIPv4Failed))
	}()

	// and the same over ipv6 reports the ipv6 bind error

	func() {
		firstServer, err := NewServer("[::1]:40000", nil, 0.0)
		check(t, err == nil)
		defer firstServer.Close()

		server, err := NewServer("[::1]:40000", nil, 0.0)
		check(t, server == nil)
		check(t, errors.Is(err, ErrServerBindSocketIPv6Failed))
	}()
}

func TestClientCreateRequiresOverrideCallbacks(t *testing.T) {
	send := func(to *Address, packetData []byte) {}
	receive := func() (packetData []byte, from Address, ok bool) { return nil, Address{}, false }

	cases := []struct {
		name    string
		address string
		config  *ClientConfig
	}{
		{"neither callback", "0.0.0.0:0", &ClientConfig{OverrideSendAndReceive: true}},
		{"missing send callback", "0.0.0.0:0", &ClientConfig{OverrideSendAndReceive: true, ReceivePacketOverride: receive}},
		{"missing receive callback", "0.0.0.0:0", &ClientConfig{OverrideSendAndReceive: true, SendPacketOverride: send}},
		{"callbacks checked before address", "not an address", &ClientConfig{OverrideSendAndReceive: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClient(tc.address, tc.config, 0.0)
			check(t, client == nil)
			check(t, errors.Is(err, ErrClientOverrideCallbacksRequired))
		})
	}

	// both callbacks supplied creates successfully

	client, err := NewClient("0.0.0.0:0", &ClientConfig{
		OverrideSendAndReceive: true,
		SendPacketOverride:     send,
		ReceivePacketOverride:  receive,
	}, 0.0)
	check(t, err == nil)
	check(t, client != nil)
	client.Close()
}

func TestServerCreateRequiresOverrideCallbacks(t *testing.T) {
	send := func(to *Address, packetData []byte) {}
	receive := func() (packetData []byte, from Address, ok bool) { return nil, Address{}, false }

	cases := []struct {
		name    string
		address string
		config  *ServerConfig
	}{
		{"neither callback", "127.0.0.1:0", &ServerConfig{OverrideSendAndReceive: true}},
		{"missing send callback", "127.0.0.1:0", &ServerConfig{OverrideSendAndReceive: true, ReceivePacketOverride: receive}},
		{"missing receive callback", "127.0.0.1:0", &ServerConfig{OverrideSendAndReceive: true, SendPacketOverride: send}},
		{"callbacks checked before address", "not an address", &ServerConfig{OverrideSendAndReceive: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, err := NewServer(tc.address, tc.config, 0.0)
			check(t, server == nil)
			check(t, errors.Is(err, ErrServerOverrideCallbacksRequired))
		})
	}

	// both callbacks supplied creates successfully

	server, err := NewServer("127.0.0.1:0", &ServerConfig{
		OverrideSendAndReceive: true,
		SendPacketOverride:     send,
		ReceivePacketOverride:  receive,
	}, 0.0)
	check(t, err == nil)
	check(t, server != nil)
	server.Close()
}

func TestOverrideCallbacksRequiredErrorNamesCallbacks(t *testing.T) {
	// the creation error should say which callbacks are required

	checkMessage := func(t *testing.T, err error) {
		t.Helper()
		check(t, err != nil)
		if err == nil {
			return
		}
		check(t, strings.Contains(err.Error(), "SendPacketOverride"))
		check(t, strings.Contains(err.Error(), "ReceivePacketOverride"))
	}

	client, err := NewClient("0.0.0.0:0", &ClientConfig{OverrideSendAndReceive: true}, 0.0)
	check(t, client == nil)
	checkMessage(t, err)

	server, err := NewServer("127.0.0.1:0", &ServerConfig{OverrideSendAndReceive: true}, 0.0)
	check(t, server == nil)
	checkMessage(t, err)
}

func TestOverrideCallbacksRequiredWithNetworkSimulator(t *testing.T) {
	// the network simulator replaces sockets, but not the override callbacks

	client, err := NewClient("127.0.0.1:40000", &ClientConfig{
		OverrideSendAndReceive: true,
		NetworkSimulator:       NewNetworkSimulator(),
	}, 0.0)
	check(t, client == nil)
	check(t, errors.Is(err, ErrClientOverrideCallbacksRequired))

	server, err := NewServer("127.0.0.1:40000", &ServerConfig{
		OverrideSendAndReceive: true,
		NetworkSimulator:       NewNetworkSimulator(),
	}, 0.0)
	check(t, server == nil)
	check(t, errors.Is(err, ErrServerOverrideCallbacksRequired))

	// with the flag off, nil callbacks are accepted

	client, err = NewClient("127.0.0.1:40000", &ClientConfig{
		NetworkSimulator: NewNetworkSimulator(),
	}, 0.0)
	check(t, err == nil)
	check(t, client != nil)
	client.Close()

	server, err = NewServer("127.0.0.1:40000", &ServerConfig{
		NetworkSimulator: NewNetworkSimulator(),
	}, 0.0)
	check(t, err == nil)
	check(t, server != nil)
	server.Close()
}

func TestNetworkSimulatorDeterminism(t *testing.T) {
	// the network simulator has its own seeded rng, so two simulators given
	// identical inputs must drop, delay and duplicate identically

	const numPackets = 100
	const maxReceive = 256

	simulatorA := NewNetworkSimulator()
	simulatorB := NewNetworkSimulator()

	simulatorA.LatencyMilliseconds = 100.0
	simulatorA.JitterMilliseconds = 50.0
	simulatorA.PacketLossPercent = 25.0
	simulatorA.DuplicatePacketPercent = 25.0

	simulatorB.LatencyMilliseconds = 100.0
	simulatorB.JitterMilliseconds = 50.0
	simulatorB.PacketLossPercent = 25.0
	simulatorB.DuplicatePacketPercent = 25.0

	from, err := ParseAddress("127.0.0.1:40000")
	check(t, err == nil)
	to, err := ParseAddress("127.0.0.1:50000")
	check(t, err == nil)

	var packetData [256]byte
	for i := 0; i < numPackets; i++ {
		for j := range packetData {
			packetData[j] = uint8(i + j)
		}
		simulatorA.SendPacket(&from, &to, packetData[:])
		simulatorB.SendPacket(&from, &to, packetData[:])
	}

	totalReceived := 0

	for currentTime := 0.0; currentTime < 2.0; currentTime += 0.01 {
		simulatorA.Update(currentTime)
		simulatorB.Update(currentTime)

		packetsA, _ := simulatorA.ReceivePackets(&to, maxReceive)
		packetsB, _ := simulatorB.ReceivePackets(&to, maxReceive)

		check(t, len(packetsA) == len(packetsB))

		for i := range packetsA {
			check(t, bytes.Equal(packetsA[i], packetsB[i]))
		}

		totalReceived += len(packetsA)
	}

	check(t, totalReceived > 0)
}

func TestClientCreate(t *testing.T) {
	requireFunctional(t)
	{
		client, err := NewClient("127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("127.0.0.1:40000")

		check(t, client.socketHolder.ipv4 != nil)
		check(t, client.socketHolder.ipv6 == nil)
		check(t, client.address.Equal(testAddress))

		client.Close()
	}

	{
		client, err := NewClient("[::]:50000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("[::]:50000")

		check(t, client.socketHolder.ipv4 == nil)
		check(t, client.socketHolder.ipv6 != nil)
		check(t, client.address.Equal(testAddress))

		client.Close()
	}

	{
		client, err := NewClientDual("127.0.0.1:40000", "[::]:50000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("127.0.0.1:40000")

		check(t, client.socketHolder.ipv4 != nil)
		check(t, client.socketHolder.ipv6 != nil)
		check(t, client.address.Equal(testAddress))

		client.Close()
	}

	{
		client, err := NewClientDual("[::]:50000", "127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("[::]:50000")

		check(t, client.socketHolder.ipv4 != nil)
		check(t, client.socketHolder.ipv6 != nil)
		check(t, client.address.Equal(testAddress))

		client.Close()
	}
}

func TestServerCreate(t *testing.T) {
	requireFunctional(t)
	{
		server, err := NewServer("127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("127.0.0.1:40000")

		check(t, server.socketHolder.ipv4 != nil)
		check(t, server.socketHolder.ipv6 == nil)
		check(t, server.address.Equal(testAddress))

		server.Close()
	}

	{
		server, err := NewServer("[::1]:50000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("[::1]:50000")

		check(t, server.socketHolder.ipv4 == nil)
		check(t, server.socketHolder.ipv6 != nil)
		check(t, server.address.Equal(testAddress))

		server.Close()
	}

	{
		server, err := NewServerDual("127.0.0.1:40000", "[::1]:50000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("127.0.0.1:40000")

		check(t, server.socketHolder.ipv4 != nil)
		check(t, server.socketHolder.ipv6 != nil)
		check(t, server.address.Equal(testAddress))

		server.Close()
	}

	{
		server, err := NewServerDual("[::1]:50000", "127.0.0.1:40000", nil, 0.0)
		check(t, err == nil)

		testAddress, _ := ParseAddress("[::1]:50000")

		check(t, server.socketHolder.ipv4 != nil)
		check(t, server.socketHolder.ipv6 != nil)
		check(t, server.address.Equal(testAddress))

		server.Close()
	}
}

func TestServerUnknownAddressDoesNotAllocateWhenLoggingOff(t *testing.T) {
	server, err := NewServer("127.0.0.1:0", &ServerConfig{ProtocolID: testProtocolID, OverrideSendAndReceive: true, SendPacketOverride: testSendPacketOverride, ReceivePacketOverride: testReceivePacketOverride}, 0.0)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)

	previousLogLevel := logLevel
	SetLogLevel(LogLevelNone)
	defer SetLogLevel(previousLogLevel)

	from, err := ParseAddress("127.0.0.1:12345")
	check(t, err == nil)

	packetData := []byte{connectionKeepAlivePacket, 0, 0, 0, 0}

	allocations := testing.AllocsPerRun(100, func() {
		server.ProcessPacket(&from, packetData)
	})

	if allocations != 0 {
		t.Fatalf("processing a packet from an unknown address allocated %v times with logging off", allocations)
	}
}

func TestSocketDropSender(t *testing.T) {
	address := os.Getenv("NETCODE_TEST_DROP_SENDER_ADDRESS")
	if address == "" {
		t.Skip("not a sender process")
	}

	datagrams, err := strconv.Atoi(os.Getenv("NETCODE_TEST_DROP_SENDER_COUNT"))
	check(t, err == nil)

	conn, err := net.Dial("udp4", address)
	check(t, err == nil)
	defer func() { _ = conn.Close() }()

	var gate [1]byte
	_, err = os.Stdin.Read(gate[:])
	check(t, err == nil)

	payload := make([]byte, 16)
	for i := 0; i < datagrams; i++ {
		_, err := conn.Write(payload)
		check(t, err == nil)
	}
}

// failingSocketReader fails every read until failures run out, then reports
// the socket closed so the reader goroutine exits.
type failingSocketReader struct {
	failures int
}

func (r *failingSocketReader) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	if r.failures == 0 {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	r.failures--
	return 0, netip.AddrPort{}, errors.New("read failed")
}

func TestSocketReadErrorsLogWhileLoggingIsConfigured(t *testing.T) {
	const failures = 1000

	previousLogLevel := logLevel
	previousPrintfFunction := printfFunction
	defer func() {
		SetLogLevel(previousLogLevel)
		SetPrintfFunction(previousPrintfFunction)
	}()

	logged := 0
	countLogs := func(format string, args ...any) { logged++ }

	backoffs := 0
	countBackoffs := func(time.Duration) { backoffs++ }

	s := &socket{packets: make(chan receivedPacket, failures)}
	done := make(chan struct{})
	go func() {
		s.readLoop(&failingSocketReader{failures: failures}, countBackoffs)
		close(done)
	}()

	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		SetLogLevel(LogLevelError)
		SetPrintfFunction(countLogs)
		s.receivePacket()
	}
	for {
		if _, ok := s.receivePacket(); !ok {
			break
		}
	}

	if logged != failures {
		t.Fatalf("%d socket read errors were logged %d times", failures, logged)
	}
	if backoffs != failures {
		t.Fatalf("%d socket read errors backed off %d times", failures, backoffs)
	}
}

func TestSocketReaderReusesBufferForDroppedPackets(t *testing.T) {
	requireFunctional(t)
	const datagrams = 2000

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	check(t, err == nil)
	defer func() { _ = conn.Close() }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestSocketDropSender$")
	cmd.Env = append(os.Environ(),
		"NETCODE_TEST_DROP_SENDER_ADDRESS="+conn.LocalAddr().String(),
		"NETCODE_TEST_DROP_SENDER_COUNT="+strconv.Itoa(datagrams),
	)

	stdin, err := cmd.StdinPipe()
	check(t, err == nil)

	check(t, cmd.Start() == nil)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	s := &socket{conn: conn, packets: make(chan receivedPacket)}
	go s.readLoop(conn, time.Sleep)

	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err = stdin.Write([]byte{1})
	check(t, err == nil)
	check(t, stdin.Close() == nil)
	check(t, cmd.Wait() == nil)

	last := before.Mallocs
	stableSince := time.Now()
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		runtime.ReadMemStats(&after)
		if after.Mallocs != last {
			last = after.Mallocs
			stableSince = time.Now()
		} else if time.Since(stableSince) >= 50*time.Millisecond {
			break
		}
		time.Sleep(time.Millisecond)
	}

	allocations := after.Mallocs - before.Mallocs
	if allocations >= datagrams/2 {
		t.Fatalf("%d datagrams dropped on a full receive channel caused %d allocations", datagrams, allocations)
	}
}

func TestServerProcessPacketZerosPrivateTokenInBuffer(t *testing.T) {
	serverAddress, err := ParseAddress("127.0.0.1:40000")
	check(t, err == nil)
	clientAddress, err := ParseAddress("127.0.0.1:50000")
	check(t, err == nil)

	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)
	inputToken := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{serverAddress}, userData)

	var encryptedConnectTokenData [connectTokenPrivateBytes]byte
	inputToken.write(encryptedConnectTokenData[:])

	// far in the future, so the request is never refused as expired before it is decrypted
	connectTokenExpireTimestamp := uint64(1) << 62
	connectTokenNonce := generateNonce()
	check(t, encryptConnectTokenPrivate(encryptedConnectTokenData[:], testProtocolID, connectTokenExpireTimestamp, connectTokenNonce[:], testPrivateKey[:]) == nil)

	requestPacket := &connectionRequest{
		versionInfo:                 versionInfo,
		protocolID:                  testProtocolID,
		connectTokenExpireTimestamp: connectTokenExpireTimestamp,
		connectTokenNonce:           connectTokenNonce,
		connectTokenData:            encryptedConnectTokenData,
	}

	var rawBuffer [maxPacketBytes]byte
	bytesWritten := writePacket(requestPacket, rawBuffer[:], 0, nil, testProtocolID)
	check(t, bytesWritten > 0)
	packetBuffer := rawBuffer[:bytesWritten]

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: NewNetworkSimulator(),
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, 1000.0)
	check(t, err == nil)
	defer server.Close()
	server.Start(1)
	server.minConnectTokenExpireTimestamp = 0

	server.ProcessPacket(&clientAddress, packetBuffer)

	// the request was decrypted and accepted, so the check below is not vacuous
	check(t, server.encryptionManager.findEncryptionMapping(&clientAddress, server.time) != -1)

	if bytes.Contains(packetBuffer, inputToken.clientToServerKey[:]) {
		t.Fatal("clientToServerKey remained in caller packetBuffer after Server.ProcessPacket")
	}
	if bytes.Contains(packetBuffer, inputToken.serverToClientKey[:]) {
		t.Fatal("serverToClientKey remained in caller packetBuffer after Server.ProcessPacket")
	}
}

func TestServerStopZeroesPrivateKey(t *testing.T) {
	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: NewNetworkSimulator(),
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, 0.0)
	check(t, err == nil)
	defer server.Close()

	server.Start(1)
	server.Stop()

	if server.config.PrivateKey != ([KeyBytes]byte{}) {
		t.Fatal("Stop did not zero the server's private key")
	}

	// the key is restored from the configuration when the server starts again
	server.Start(1)
	if server.config.PrivateKey != testPrivateKey {
		t.Fatal("Start did not restore the server's private key")
	}
}

func TestServerIgnoredConnectionRequestClearsTokenData(t *testing.T) {
	serverAddress, err := ParseAddress("127.0.0.1:40000")
	check(t, err == nil)
	clientAddress, err := ParseAddress("127.0.0.1:50000")
	check(t, err == nil)

	userData := make([]byte, UserDataBytes)
	RandomBytes(userData)
	inputToken := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{serverAddress}, userData)

	var connectTokenData [connectTokenPrivateBytes]byte
	inputToken.write(connectTokenData[:])

	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: NewNetworkSimulator(),
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, 1000.0)
	check(t, err == nil)
	defer server.Close()

	server.flags = serverFlagIgnoreConnectionRequestPackets

	request := &connectionRequest{
		versionInfo:                 versionInfo,
		protocolID:                  testProtocolID,
		connectTokenExpireTimestamp: uint64(1) << 62,
		connectTokenData:            connectTokenData,
	}
	server.processPacketInternal(&clientAddress, request, 0, -1, -1, 0)

	if bytes.Contains(request.connectTokenData[:], inputToken.clientToServerKey[:]) {
		t.Fatal("clientToServerKey remained in an ignored connection request")
	}
	if bytes.Contains(request.connectTokenData[:], inputToken.serverToClientKey[:]) {
		t.Fatal("serverToClientKey remained in an ignored connection request")
	}
}

func TestServerStopBeforeStartZeroesPrivateKey(t *testing.T) {
	serverConfig := &ServerConfig{
		ProtocolID:       testProtocolID,
		PrivateKey:       testPrivateKey,
		NetworkSimulator: NewNetworkSimulator(),
	}
	server, err := NewServer("127.0.0.1:40000", serverConfig, 0.0)
	check(t, err == nil)
	defer server.Close()

	server.Stop()

	if server.config.PrivateKey != ([KeyBytes]byte{}) {
		t.Fatal("Stop before Start did not zero the server's private key")
	}
}

func TestEncryptionManagerZerosKeysOfExpiredMappings(t *testing.T) {
	var zeroKey [KeyBytes]byte

	address := func(port uint16) Address {
		return Address{Type: AddressIPv4, IPv4: [4]byte{127, 0, 0, 1}, Port: port}
	}

	currentTime := 1000.0
	expiredTime := currentTime + testTimeoutSeconds*2

	// removing the last mapping trims the expired, unowned mappings behind it.
	// a mapping owned by a connected client is never trimmed and keeps its keys.
	{
		var manager encryptionManager
		manager.reset()

		addresses := []Address{address(20000), address(20001), address(20002)}
		for i := range addresses {
			check(t, manager.addEncryptionMapping(&addresses[i], GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))
		}
		manager.clientIndex[0] = 0
		ownedSendKey := manager.sendKey[0]
		ownedReceiveKey := manager.receiveKey[0]

		check(t, manager.removeEncryptionMapping(&addresses[2], expiredTime))
		check(t, manager.numEncryptionMappings == 1)

		for i := 1; i < len(addresses); i++ {
			if manager.sendKey[i] != zeroKey || manager.receiveKey[i] != zeroKey {
				t.Fatalf("keys of trimmed encryption mapping %d were not zeroed", i)
			}
		}
		check(t, manager.sendKey[0] == ownedSendKey)
		check(t, manager.receiveKey[0] == ownedReceiveKey)
	}

	// looking up an expired, unowned mapping zeros its keys. an owned one keeps them.
	{
		var manager encryptionManager
		manager.reset()

		unowned := address(30000)
		owned := address(30001)
		check(t, manager.addEncryptionMapping(&unowned, GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))
		check(t, manager.addEncryptionMapping(&owned, GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))
		manager.clientIndex[1] = 0
		ownedSendKey := manager.sendKey[1]
		ownedReceiveKey := manager.receiveKey[1]

		check(t, manager.findEncryptionMapping(&unowned, expiredTime) == -1)
		check(t, manager.findEncryptionMapping(&owned, expiredTime) == -1)

		if manager.sendKey[0] != zeroKey || manager.receiveKey[0] != zeroKey {
			t.Fatal("keys of expired encryption mapping were not zeroed on lookup")
		}
		check(t, manager.sendKey[1] == ownedSendKey)
		check(t, manager.receiveKey[1] == ownedReceiveKey)
	}

	// looking up or adding a different address zeros the keys of every expired, unowned mapping.
	// an add reuses the first expired slot, so the check is on the second one.
	for _, add := range []bool{false, true} {
		var manager encryptionManager
		manager.reset()

		first := address(40000)
		second := address(40001)
		owned := address(40002)
		other := address(40003)
		check(t, manager.addEncryptionMapping(&first, GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))
		check(t, manager.addEncryptionMapping(&second, GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))
		check(t, manager.addEncryptionMapping(&owned, GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))
		manager.clientIndex[2] = 0
		ownedSendKey := manager.sendKey[2]
		ownedReceiveKey := manager.receiveKey[2]

		if add {
			check(t, manager.addEncryptionMapping(&other, GenerateKey(), GenerateKey(), expiredTime, -1.0, testTimeoutSeconds, -1))
			check(t, manager.address[0].Equal(other))
		} else {
			check(t, manager.findEncryptionMapping(&other, expiredTime) == -1)
			if manager.sendKey[0] != zeroKey || manager.receiveKey[0] != zeroKey {
				t.Fatal("keys of expired encryption mapping were not zeroed on lookup of another address")
			}
		}

		if manager.sendKey[1] != zeroKey || manager.receiveKey[1] != zeroKey {
			t.Fatalf("keys of expired encryption mapping were not zeroed (add=%v)", add)
		}
		check(t, manager.sendKey[2] == ownedSendKey)
		check(t, manager.receiveKey[2] == ownedReceiveKey)
	}

	// the server's update zeros the keys of expired, unowned mappings with no lookups at all.
	{
		serverConfig := &ServerConfig{
			ProtocolID:       testProtocolID,
			PrivateKey:       testPrivateKey,
			NetworkSimulator: NewNetworkSimulator(),
		}
		server, err := NewServer("127.0.0.1:40000", serverConfig, currentTime)
		check(t, err == nil)
		defer server.Close()
		server.Start(1)

		expired := address(50000)
		check(t, server.encryptionManager.addEncryptionMapping(&expired, GenerateKey(), GenerateKey(), currentTime, -1.0, testTimeoutSeconds, -1))

		server.Update(expiredTime)

		if server.encryptionManager.sendKey[0] != zeroKey || server.encryptionManager.receiveKey[0] != zeroKey {
			t.Fatal("keys of expired encryption mapping were not zeroed by the server update")
		}
	}
}

func TestSocketBufferSizeBackOff(t *testing.T) {
	const requested = 4 * 1024 * 1024

	t.Run("accepts the request on the first try", func(t *testing.T) {
		calls := 0
		set := func(size int) error {
			calls++
			if size != requested {
				return errors.New("buffer size refused")
			}
			return nil
		}

		size, ok := setSocketBufferSize(requested, set)
		check(t, ok)
		check(t, size == requested)
		check(t, calls == 1)
	})

	t.Run("backs off by powers of two to 65536", func(t *testing.T) {
		const accepted = 65536
		var attempted []int
		set := func(size int) error {
			attempted = append(attempted, size)
			if size == accepted {
				return nil
			}
			return errors.New("buffer size refused")
		}

		size, ok := setSocketBufferSize(requested, set)
		check(t, ok)
		check(t, size == accepted)

		want := []int{
			4 * 1024 * 1024,
			2 * 1024 * 1024,
			1 * 1024 * 1024,
			512 * 1024,
			256 * 1024,
			128 * 1024,
			65536,
		}
		check(t, len(attempted) == len(want))
		for i := range want {
			check(t, attempted[i] == want[i])
		}
	})

	// A stock NetBSD refuses anything over about 227 KiB, including 256 KiB.
	t.Run("accepts 128KiB when 256KiB is refused", func(t *testing.T) {
		const limit = 227 * 1024
		calls := 0
		set := func(size int) error {
			calls++
			if size <= limit {
				return nil
			}
			return errors.New("buffer size refused")
		}

		size, ok := setSocketBufferSize(requested, set)
		check(t, ok)
		check(t, size == 128*1024)
		check(t, calls == 6)
	})

	t.Run("keeps the OS default when every size is refused", func(t *testing.T) {
		var attempted []int
		set := func(size int) error {
			attempted = append(attempted, size)
			return errors.New("buffer size refused")
		}

		size, ok := setSocketBufferSize(requested, set)
		check(t, !ok)
		check(t, size == 0)
		check(t, len(attempted) == 7)
		check(t, attempted[len(attempted)-1] == 65536)
	})

	t.Run("does not try a request already below 65536", func(t *testing.T) {
		calls := 0
		set := func(int) error {
			calls++
			return nil
		}

		size, ok := setSocketBufferSize(32*1024, set)
		check(t, !ok)
		check(t, size == 0)
		check(t, calls == 0)
	})
}
