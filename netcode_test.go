package netcode

import (
	"bytes"
	"errors"
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
)

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

	expireTimestamp := uint64(time.Now().Unix()) + 30
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

	connectTokenExpireTimestamp := uint64(time.Now().Unix()) + 30
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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), connectTokenKey, &allowedPackets, nil).(*connectionRequest)

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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), nil, &allowedPackets, nil).(*connectionDenied)

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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), nil, &allowedPackets, nil).(*connectionChallenge)

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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), nil, &allowedPackets, nil).(*connectionResponse)

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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), nil, &allowedPackets, nil).(*connectionKeepAlive)

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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), nil, &allowedPackets, nil).(*connectionPayload)

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

	outputPacket, ok := readPacket(buffer[:bytesWritten], &sequence, packetKey, testProtocolID, uint64(time.Now().Unix()), nil, &allowedPackets, nil).(*connectionDisconnect)

	check(t, ok)
	check(t, outputPacket != nil)
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

	createTimestamp := uint64(time.Now().Unix())
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

		check(t, manager.addEncryptionMapping(&mappings[i].address, mappings[i].sendKey, mappings[i].receiveKey, currentTime, -1.0, testTimeoutSeconds))

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

	check(t, manager.addEncryptionMapping(&mappings[0].address, mappings[0].sendKey, mappings[0].receiveKey, currentTime, -1.0, testTimeoutSeconds))
	check(t, manager.addEncryptionMapping(&mappings[numEncryptionMappings-1].address, mappings[numEncryptionMappings-1].sendKey, mappings[numEncryptionMappings-1].receiveKey, currentTime, -1.0, testTimeoutSeconds))

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

		check(t, manager.addEncryptionMapping(&mappings[i].address, mappings[i].sendKey, mappings[i].receiveKey, currentTime, -1.0, testTimeoutSeconds))

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

	check(t, manager.addEncryptionMapping(&mappings[0].address, mappings[0].sendKey, mappings[0].receiveKey, currentTime, currentTime+1.0, testTimeoutSeconds))

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
}

func TestRuntimeGuards(t *testing.T) {
	// out of range arguments to public entry points must not crash or corrupt state

	// no private key needed: nothing in this test decrypts anything

	serverConfig := &ServerConfig{ProtocolID: testProtocolID}

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

func TestInitAndDefaults(t *testing.T) {
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
