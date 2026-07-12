package netcode

import (
	"bytes"
	"testing"
)

// These fuzz targets are ports of the libFuzzer harnesses in the C reference
// implementation (fuzz/fuzz_read_packet.c, fuzz_parse_address.c and
// fuzz_connect_token.c), using Go's native fuzzing. Run them with e.g.
//
//	go test -fuzz=FuzzReadPacket -fuzztime=60s
//
// The regular test run executes the seed corpus for each target.

// fuzzInput consumes structured fields from a fuzz-provided byte slice,
// returning zeros once the input is exhausted, like fuzz.h in the C harnesses.
type fuzzInput struct {
	data   []byte
	offset int
}

func (in *fuzzInput) u8() uint8 {
	if in.offset >= len(in.data) {
		return 0
	}
	value := in.data[in.offset]
	in.offset++
	return value
}

func (in *fuzzInput) u16() uint16 {
	return uint16(in.u8()) | uint16(in.u8())<<8
}

func (in *fuzzInput) u64() uint64 {
	var value uint64
	for i := 0; i < 8; i++ {
		value |= uint64(in.u8()) << (8 * i)
	}
	return value
}

func (in *fuzzInput) read(buffer []byte) {
	for i := range buffer {
		buffer[i] = in.u8()
	}
}

var fuzzPacketKey = bytes.Repeat([]byte{0xAA}, KeyBytes)
var fuzzPrivateKey = bytes.Repeat([]byte{0xBB}, KeyBytes)

func fuzzReadPacket(buffer []byte, sequence *uint64, replay *replayProtection) packet {
	allowedPackets := allPacketsAllowed()
	return readPacket(buffer,
		sequence,
		fuzzPacketKey,
		testProtocolID,
		0, // current timestamp: zero so fuzz-chosen expire timestamps pass
		fuzzPrivateKey,
		&allowedPackets,
		replay)
}

// FuzzReadPacket feeds raw bytes straight into readPacket, the primary
// hostile-input surface: every byte a netcode server or client accepts off a
// socket goes through this function. This exercises all parsing and rejection
// ahead of AEAD authentication (a fuzzer cannot forge a valid MAC, so
// decryption is expected to fail here).
func FuzzReadPacket(f *testing.F) {
	// seed the corpus with one valid packet of each type

	seedPackets := []packet{
		&connectionDenied{},
		&connectionChallenge{challengeTokenSequence: 1000},
		&connectionResponse{challengeTokenSequence: 1000},
		&connectionKeepAlive{clientIndex: 10, maxClients: 16},
		&connectionPayload{payloadData: make([]byte, maxPayloadBytes)},
		&connectionDisconnect{},
	}
	for _, seedPacket := range seedPackets {
		var buffer [maxPacketBytes]byte
		packetBytes := writePacket(seedPacket, buffer[:], 1000, fuzzPacketKey, testProtocolID)
		f.Add(buffer[:packetBytes])
	}

	{
		request := &connectionRequest{
			versionInfo:                 versionInfo,
			protocolID:                  testProtocolID,
			connectTokenExpireTimestamp: 1,
		}
		if encryptConnectTokenPrivate(request.connectTokenData[:], testProtocolID, 1, request.connectTokenNonce[:], fuzzPrivateKey) != nil {
			f.Fatal("failed to encrypt connect token")
		}
		var buffer [maxPacketBytes]byte
		packetBytes := writePacket(request, buffer[:], 1000, fuzzPacketKey, testProtocolID)
		f.Add(buffer[:packetBytes])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPacketBytes {
			data = data[:maxPacketBytes]
		}

		// readPacket decrypts in place, so work on a copy
		buffer := append([]byte(nil), data...)

		var replay replayProtection
		replay.reset()

		var sequence uint64
		fuzzReadPacket(buffer, &sequence, &replay)
	})
}

// FuzzWriteReadPacketRoundTrip builds a packet from fuzz-derived fields,
// writes and encrypts it with the real keys, optionally corrupts one byte,
// then reads it back. This drives the post-decryption parsing, and asserts the
// round-trip property: an uncorrupted packet written by writePacket must read
// back with the same type and sequence. Connection requests get their connect
// token encrypted with the real private key, so the full request path
// including token decrypt and read is covered.
func FuzzWriteReadPacketRoundTrip(f *testing.F) {
	f.Add(uint8(connectionRequestPacket), uint64(1000), false, uint16(0), uint8(0), []byte("seed"))
	f.Add(uint8(connectionChallengePacket), uint64(0), false, uint16(0), uint8(0), []byte("seed"))
	f.Add(uint8(connectionPayloadPacket), uint64(0xFFFFFFFFFFFFFFFF), false, uint16(0), uint8(0), []byte("seed"))
	f.Add(uint8(connectionPayloadPacket), uint64(1000), true, uint16(10), uint8(0xFF), []byte("seed"))

	f.Fuzz(func(t *testing.T, packetTypeByte uint8, sequence uint64, corrupt bool, corruptOffset uint16, corruptXor uint8, data []byte) {
		packetType := packetTypeByte % connectionNumPackets

		in := &fuzzInput{data: data}

		// build the packet struct for the chosen type from fuzz input

		var inputPacket packet

		switch packetType {
		case connectionRequestPacket:
			// encrypt a connect token with the real private key so the read side can
			// fully decrypt and accept the request
			expireTimestamp := in.u64()
			if expireTimestamp == 0 {
				expireTimestamp = 1
			}
			request := &connectionRequest{
				versionInfo:                 versionInfo,
				protocolID:                  testProtocolID,
				connectTokenExpireTimestamp: expireTimestamp,
			}
			in.read(request.connectTokenNonce[:])
			in.read(request.connectTokenData[:connectTokenPrivateBytes-MacBytes])
			if encryptConnectTokenPrivate(request.connectTokenData[:], testProtocolID, expireTimestamp, request.connectTokenNonce[:], fuzzPrivateKey) != nil {
				return
			}
			inputPacket = request

		case connectionDeniedPacket:
			inputPacket = &connectionDenied{}

		case connectionChallengePacket:
			challenge := &connectionChallenge{challengeTokenSequence: in.u64()}
			in.read(challenge.challengeTokenData[:])
			inputPacket = challenge

		case connectionResponsePacket:
			response := &connectionResponse{challengeTokenSequence: in.u64()}
			in.read(response.challengeTokenData[:])
			inputPacket = response

		case connectionKeepAlivePacket:
			inputPacket = &connectionKeepAlive{
				clientIndex: int32(in.u16()),
				maxClients:  int32(in.u16()),
			}

		case connectionPayloadPacket:
			payloadBytes := 1 + int(in.u16())%maxPayloadBytes
			payload := &connectionPayload{payloadData: make([]byte, payloadBytes)}
			in.read(payload.payloadData)
			inputPacket = payload

		case connectionDisconnectPacket:
			inputPacket = &connectionDisconnect{}
		}

		// write the packet, optionally corrupt one byte, then read it back

		var buffer [maxPacketBytes]byte
		packetBytes := writePacket(inputPacket, buffer[:], sequence, fuzzPacketKey, testProtocolID)
		if packetBytes <= 0 {
			t.Fatalf("failed to write packet type %d", packetType)
		}

		corrupted := false
		if corrupt && corruptXor != 0 {
			buffer[int(corruptOffset)%packetBytes] ^= corruptXor
			corrupted = true
		}

		var readSequence uint64
		outputPacket := fuzzReadPacket(buffer[:packetBytes], &readSequence, nil)

		if !corrupted {
			if outputPacket == nil {
				t.Fatalf("uncorrupted packet type %d failed to read back", packetType)
			}
			if outputPacket.packetType() != packetType {
				t.Fatalf("packet type changed in round trip: wrote %d, read %d", packetType, outputPacket.packetType())
			}
			if packetType != connectionRequestPacket && readSequence != sequence {
				t.Fatalf("sequence changed in round trip: wrote %d, read %d", sequence, readSequence)
			}
		}
	})
}

// FuzzParseAddress fuzzes ParseAddress. Address strings come from the game's
// backend via connect tokens and from application code, so the parser deserves
// adversarial input. Also checks the round trip property: any address that
// parses must survive Address.String -> ParseAddress unchanged.
func FuzzParseAddress(f *testing.F) {
	seeds := []string{
		"127.0.0.1",
		"127.0.0.1:40000",
		"107.77.207.77:65535",
		"::",
		"::1",
		"fe80::202:b3ff:fe1e:8329",
		"[::1]",
		"[fe80::1]:5",
		"[::]:40000",
		"[",
		"[]:",
		"...",
		"127.0.0.1:40k",
		"::ffff:1.2.3.4",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, addressString string) {
		address, err := ParseAddress(addressString)
		if err != nil {
			return
		}

		roundTrip, err := ParseAddress(address.String())
		if err != nil {
			t.Fatalf("address %q parsed to %q which failed to parse back: %v", addressString, address.String(), err)
		}
		if !address.Equal(roundTrip) {
			t.Fatalf("address %q did not survive round trip: %q parsed to %q", addressString, address.String(), roundTrip.String())
		}
	})
}

// FuzzReadConnectToken raw fuzzes the public connect token reader. The public
// connect token is read by the client from whatever the game's backend
// returned: a parser over untrusted bytes.
func FuzzReadConnectToken(f *testing.F) {
	{
		seed, err := GenerateConnectToken([]string{"127.0.0.1:40000"}, []string{"127.0.0.1:40000"},
			testConnectTokenExpiry, testTimeoutSeconds, testClientID, testProtocolID, testPrivateKey[:], nil)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var buffer [ConnectTokenBytes]byte
		copy(buffer[:], data)

		var token connectToken
		_ = token.read(buffer[:])
	})
}

// FuzzReadConnectTokenPrivate raw fuzzes the private connect token reader,
// which the server runs over the decrypted portion of a connection request
// packet.
func FuzzReadConnectTokenPrivate(f *testing.F) {
	{
		token := generateConnectTokenPrivate(testClientID, testTimeoutSeconds, []Address{testServerAddress()}, nil)
		var seed [connectTokenPrivateBytes]byte
		token.write(seed[:])
		f.Add(seed[:])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var buffer [connectTokenPrivateBytes]byte
		copy(buffer[:], data)

		var token connectTokenPrivate
		_ = token.read(buffer[:])
	})
}

// FuzzConnectTokenPrivateRoundTrip builds a valid private connect token from
// fuzz-derived fields, writes it, reads it back, and checks the fields
// survive.
func FuzzConnectTokenPrivateRoundTrip(f *testing.F) {
	f.Add([]byte("seed"))

	f.Fuzz(func(t *testing.T, data []byte) {
		in := &fuzzInput{data: data}

		var inputToken connectTokenPrivate
		inputToken.clientID = in.u64()
		inputToken.timeoutSeconds = int32(in.u16())
		inputToken.numServerAddresses = 1 + int(in.u8())%MaxServersPerConnect

		for i := 0; i < inputToken.numServerAddresses; i++ {
			address := &inputToken.serverAddresses[i]
			if in.u8()&1 == 0 {
				address.Type = AddressIPv4
				in.read(address.IPv4[:])
			} else {
				address.Type = AddressIPv6
				for j := 0; j < 8; j++ {
					address.IPv6[j] = in.u16()
				}
			}
			address.Port = in.u16()
		}

		in.read(inputToken.clientToServerKey[:])
		in.read(inputToken.serverToClientKey[:])
		in.read(inputToken.userData[:])

		var buffer [connectTokenPrivateBytes]byte
		inputToken.write(buffer[:])

		var outputToken connectTokenPrivate
		if err := outputToken.read(buffer[:]); err != nil {
			t.Fatalf("valid private connect token failed to read back: %v", err)
		}

		if outputToken != inputToken {
			t.Fatal("private connect token did not survive round trip")
		}
	})
}
