package netcode

// Packet types.
const (
	connectionRequestPacket    = 0
	connectionDeniedPacket     = 1
	connectionChallengePacket  = 2
	connectionResponsePacket   = 3
	connectionKeepAlivePacket  = 4
	connectionPayloadPacket    = 5
	connectionDisconnectPacket = 6
	connectionNumPackets       = 7
)

// packet is implemented by each of the packet structs below.
type packet interface {
	packetType() uint8
}

// connectionRequest is the only unencrypted packet. It wraps the encrypted
// private connect token data, which only the server can decrypt.
type connectionRequest struct {
	versionInfo                 [versionInfoBytes]byte
	protocolID                  uint64
	connectTokenExpireTimestamp uint64
	connectTokenNonce           [connectTokenNonceBytes]byte
	connectTokenData            [connectTokenPrivateBytes]byte
}

type connectionDenied struct{}

type connectionChallenge struct {
	challengeTokenSequence uint64
	challengeTokenData     [challengeTokenBytes]byte
}

type connectionResponse struct {
	challengeTokenSequence uint64
	challengeTokenData     [challengeTokenBytes]byte
}

type connectionKeepAlive struct {
	clientIndex int32
	maxClients  int32
}

type connectionPayload struct {
	payloadData []byte
}

type connectionDisconnect struct{}

func (*connectionRequest) packetType() uint8    { return connectionRequestPacket }
func (*connectionDenied) packetType() uint8     { return connectionDeniedPacket }
func (*connectionChallenge) packetType() uint8  { return connectionChallengePacket }
func (*connectionResponse) packetType() uint8   { return connectionResponsePacket }
func (*connectionKeepAlive) packetType() uint8  { return connectionKeepAlivePacket }
func (*connectionPayload) packetType() uint8    { return connectionPayloadPacket }
func (*connectionDisconnect) packetType() uint8 { return connectionDisconnectPacket }

// sequenceNumberBytesRequired returns the number of bytes needed to encode a
// sequence number, omitting high zero bytes, in [1,8].
func sequenceNumberBytesRequired(sequence uint64) int {
	mask := uint64(0xFF00000000000000)
	i := 0
	for ; i < 7; i++ {
		if sequence&mask != 0 {
			break
		}
		mask >>= 8
	}
	return 8 - i
}

// packetAdditionalData builds the associated data for encrypted packets:
// version info, protocol id and the packet prefix byte. This stops an attacker
// from modifying the packet type.
func packetAdditionalData(protocolID uint64, prefixByte uint8) [versionInfoBytes + 8 + 1]byte {
	var additional [versionInfoBytes + 8 + 1]byte
	w := writer{buffer: additional[:]}
	w.bytes(versionInfo[:])
	w.uint64(protocolID)
	w.uint8(prefixByte)
	return additional
}

// writePacket writes a packet to the buffer, encrypting all packet types
// except connection request. Returns the number of bytes written, or zero if
// the packet failed to write.
func writePacket(p packet, buffer []byte, sequence uint64, writePacketKey []byte, protocolID uint64) int {
	if request, ok := p.(*connectionRequest); ok {
		// connection request packet: first byte is zero, not encrypted

		w := writer{buffer: buffer}
		w.uint8(connectionRequestPacket)
		w.bytes(request.versionInfo[:])
		w.uint64(request.protocolID)
		w.uint64(request.connectTokenExpireTimestamp)
		w.bytes(request.connectTokenNonce[:])
		w.bytes(request.connectTokenData[:])
		return w.pos
	}

	// *** encrypted packets ***

	// write the prefix byte (this is a combination of the packet type and number of sequence bytes)

	w := writer{buffer: buffer}

	sequenceBytes := sequenceNumberBytesRequired(sequence)

	prefixByte := p.packetType() | uint8(sequenceBytes)<<4

	w.uint8(prefixByte)

	// write the variable length sequence number [1,8] bytes.

	sequenceTemp := sequence
	for i := 0; i < sequenceBytes; i++ {
		w.uint8(uint8(sequenceTemp & 0xFF))
		sequenceTemp >>= 8
	}

	// write packet data according to type. this data will be encrypted.

	encryptedStart := w.pos

	switch t := p.(type) {
	case *connectionDenied:
		// ...

	case *connectionChallenge:
		w.uint64(t.challengeTokenSequence)
		w.bytes(t.challengeTokenData[:])

	case *connectionResponse:
		w.uint64(t.challengeTokenSequence)
		w.bytes(t.challengeTokenData[:])

	case *connectionKeepAlive:
		w.uint32(uint32(t.clientIndex))
		w.uint32(uint32(t.maxClients))

	case *connectionPayload:
		w.bytes(t.payloadData)

	case *connectionDisconnect:
		// ...

	default:
		panic("netcode: invalid packet type")
	}

	encryptedFinish := w.pos

	// encrypt the per-packet data written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

	additional := packetAdditionalData(protocolID, prefixByte)

	nonce := packetNonce(sequence)

	if err := encryptAEAD(buffer[encryptedStart:], encryptedFinish-encryptedStart, additional[:], nonce[:], writePacketKey); err != nil {
		return 0
	}

	return encryptedFinish + MacBytes
}

// readPacket reads and validates a packet, in the exact order required by the
// standard, decrypting it with readPacketKey (or, for connection request
// packets, decrypting the inner private connect token with privateKey).
// Returns the packet and its sequence number, or nil if the packet should be
// ignored for any reason.
func readPacket(buffer []byte,
	sequence *uint64,
	readPacketKey []byte,
	protocolID uint64,
	currentTimestamp uint64,
	privateKey []byte,
	allowedPackets *[connectionNumPackets]bool,
	replayProtection *replayProtection) packet {

	*sequence = 0

	bufferLength := len(buffer)

	if bufferLength < 1 {
		printf(LogLevelDebug, "ignored packet. buffer length is less than 1\n")
		return nil
	}

	r := reader{buffer: buffer}

	prefixByte := r.uint8()

	if prefixByte == connectionRequestPacket {
		// connection request packet: first byte is zero

		if !allowedPackets[connectionRequestPacket] {
			printf(LogLevelDebug, "ignored connection request packet. packet type is not allowed\n")
			return nil
		}

		if bufferLength != 1+versionInfoBytes+8+8+connectTokenNonceBytes+connectTokenPrivateBytes {
			printf(LogLevelDebug, "ignored connection request packet. bad packet length (expected %d, got %d)\n",
				1+versionInfoBytes+8+8+connectTokenNonceBytes+connectTokenPrivateBytes, bufferLength)
			return nil
		}

		if privateKey == nil {
			printf(LogLevelDebug, "ignored connection request packet. no private key\n")
			return nil
		}

		var packetVersionInfo [versionInfoBytes]byte
		r.bytes(packetVersionInfo[:])
		if packetVersionInfo != versionInfo {
			printf(LogLevelDebug, "ignored connection request packet. bad version info\n")
			return nil
		}

		packetProtocolID := r.uint64()
		if packetProtocolID != protocolID {
			printf(LogLevelDebug, "ignored connection request packet. wrong protocol id. expected %.16x, got %.16x\n", protocolID, packetProtocolID)
			return nil
		}

		packetConnectTokenExpireTimestamp := r.uint64()
		if packetConnectTokenExpireTimestamp <= currentTimestamp {
			printf(LogLevelDebug, "ignored connection request packet. connect token expired\n")
			return nil
		}

		var packetConnectTokenNonce [connectTokenNonceBytes]byte
		r.bytes(packetConnectTokenNonce[:])

		if decryptConnectTokenPrivate(buffer[r.pos:],
			protocolID,
			packetConnectTokenExpireTimestamp,
			packetConnectTokenNonce[:],
			privateKey) != nil {
			printf(LogLevelDebug, "ignored connection request packet. connect token failed to decrypt\n")
			return nil
		}

		request := &connectionRequest{
			versionInfo:                 packetVersionInfo,
			protocolID:                  packetProtocolID,
			connectTokenExpireTimestamp: packetConnectTokenExpireTimestamp,
			connectTokenNonce:           packetConnectTokenNonce,
		}
		r.bytes(request.connectTokenData[:])

		return request
	}

	// *** encrypted packets ***

	if readPacketKey == nil {
		printf(LogLevelDebug, "ignored encrypted packet. no read packet key for this address\n")
		return nil
	}

	if bufferLength < 1+1+MacBytes {
		printf(LogLevelDebug, "ignored encrypted packet. packet is too small to be valid (%d bytes)\n", bufferLength)
		return nil
	}

	// extract the packet type and number of sequence bytes from the prefix byte

	packetType := prefixByte & 0xF

	if packetType >= connectionNumPackets {
		printf(LogLevelDebug, "ignored encrypted packet. packet type %d is invalid\n", packetType)
		return nil
	}

	if !allowedPackets[packetType] {
		printf(LogLevelDebug, "ignored encrypted packet. packet type %d is not allowed\n", packetType)
		return nil
	}

	sequenceBytes := int(prefixByte >> 4)

	if sequenceBytes < 1 || sequenceBytes > 8 {
		printf(LogLevelDebug, "ignored encrypted packet. sequence bytes %d is out of range [1,8]\n", sequenceBytes)
		return nil
	}

	if bufferLength < 1+sequenceBytes+MacBytes {
		printf(LogLevelDebug, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n")
		return nil
	}

	// read variable length sequence number [1,8]

	for i := 0; i < sequenceBytes; i++ {
		value := r.uint8()
		*sequence |= uint64(value) << (8 * i)
	}

	// ignore the packet if it has already been received

	if replayProtection != nil && packetType >= connectionKeepAlivePacket {
		if replayProtection.alreadyReceived(*sequence) {
			printf(LogLevelDebug, "ignored packet. sequence %.16x already received (replay protection)\n", *sequence)
			return nil
		}
	}

	// decrypt the per-packet type data

	additional := packetAdditionalData(protocolID, prefixByte)

	nonce := packetNonce(*sequence)

	encryptedBytes := bufferLength - r.pos

	if encryptedBytes < MacBytes {
		printf(LogLevelDebug, "ignored encrypted packet. encrypted payload is too small\n")
		return nil
	}

	if decryptAEAD(buffer[r.pos:], encryptedBytes, additional[:], nonce[:], readPacketKey) != nil {
		printf(LogLevelDebug, "ignored encrypted packet. failed to decrypt\n")
		return nil
	}

	decryptedBytes := encryptedBytes - MacBytes

	// update the latest replay protection sequence #

	if replayProtection != nil && packetType >= connectionKeepAlivePacket {
		replayProtection.advanceSequence(*sequence)
	}

	// process the per-packet type data that was just decrypted

	switch packetType {
	case connectionDeniedPacket:
		if decryptedBytes != 0 {
			printf(LogLevelDebug, "ignored connection denied packet. decrypted packet data is wrong size\n")
			return nil
		}
		return &connectionDenied{}

	case connectionChallengePacket:
		if decryptedBytes != 8+challengeTokenBytes {
			printf(LogLevelDebug, "ignored connection challenge packet. decrypted packet data is wrong size\n")
			return nil
		}
		challenge := &connectionChallenge{}
		challenge.challengeTokenSequence = r.uint64()
		r.bytes(challenge.challengeTokenData[:])
		return challenge

	case connectionResponsePacket:
		if decryptedBytes != 8+challengeTokenBytes {
			printf(LogLevelDebug, "ignored connection response packet. decrypted packet data is wrong size\n")
			return nil
		}
		response := &connectionResponse{}
		response.challengeTokenSequence = r.uint64()
		r.bytes(response.challengeTokenData[:])
		return response

	case connectionKeepAlivePacket:
		if decryptedBytes != 8 {
			printf(LogLevelDebug, "ignored connection keep alive packet. decrypted packet data is wrong size\n")
			return nil
		}
		keepAlive := &connectionKeepAlive{}
		keepAlive.clientIndex = int32(r.uint32())
		keepAlive.maxClients = int32(r.uint32())
		return keepAlive

	case connectionPayloadPacket:
		if decryptedBytes < 1 {
			printf(LogLevelDebug, "ignored connection payload packet. payload is too small\n")
			return nil
		}
		if decryptedBytes > maxPayloadBytes {
			printf(LogLevelDebug, "ignored connection payload packet. payload is too large\n")
			return nil
		}
		payload := &connectionPayload{payloadData: make([]byte, decryptedBytes)}
		r.bytes(payload.payloadData)
		return payload

	case connectionDisconnectPacket:
		if decryptedBytes != 0 {
			printf(LogLevelDebug, "ignored connection disconnect packet. decrypted packet data is wrong size\n")
			return nil
		}
		return &connectionDisconnect{}

	default:
		return nil
	}
}
