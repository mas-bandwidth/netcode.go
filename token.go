package netcode

import (
	"errors"
	"fmt"
	"time"
)

// ----------------------------------------------------------------
// private connect token

// connectTokenPrivate is the private portion of a connect token. It is
// encrypted and signed with a private key shared between the web backend and
// dedicated server instances.
type connectTokenPrivate struct {
	clientID           uint64
	timeoutSeconds     int32
	numServerAddresses int
	serverAddresses    [MaxServersPerConnect]Address
	clientToServerKey  [KeyBytes]byte
	serverToClientKey  [KeyBytes]byte
	userData           [UserDataBytes]byte
}

func generateConnectTokenPrivate(clientID uint64, timeoutSeconds int32, serverAddresses []Address, userData []byte) *connectTokenPrivate {
	token := &connectTokenPrivate{
		clientID:           clientID,
		timeoutSeconds:     timeoutSeconds,
		numServerAddresses: len(serverAddresses),
	}
	copy(token.serverAddresses[:], serverAddresses)
	RandomBytes(token.clientToServerKey[:])
	RandomBytes(token.serverToClientKey[:])
	copy(token.userData[:], userData)
	return token
}

func writeAddress(w *writer, address *Address) {
	switch address.Type {
	case AddressIPv4:
		w.uint8(AddressIPv4)
		w.bytes(address.IPv4[:])
		w.uint16(address.Port)
	case AddressIPv6:
		w.uint8(AddressIPv6)
		for i := 0; i < 8; i++ {
			w.uint16(address.IPv6[i])
		}
		w.uint16(address.Port)
	default:
		panic("netcode: invalid address type")
	}
}

func readAddress(r *reader, address *Address) error {
	address.Type = r.uint8()
	switch address.Type {
	case AddressIPv4:
		r.bytes(address.IPv4[:])
		address.Port = r.uint16()
	case AddressIPv6:
		for i := 0; i < 8; i++ {
			address.IPv6[i] = r.uint16()
		}
		address.Port = r.uint16()
	default:
		return fmt.Errorf("netcode: bad address type (%d)", address.Type)
	}
	return nil
}

// writeConnectTokenPrivate writes the private connect token to a fixed size
// buffer of connectTokenPrivateBytes (1024). Unused bytes are zero padded.
func (token *connectTokenPrivate) write(buffer []byte) {
	w := writer{buffer: buffer}

	w.uint64(token.clientID)
	w.uint32(uint32(token.timeoutSeconds))
	w.uint32(uint32(token.numServerAddresses))

	for i := 0; i < token.numServerAddresses; i++ {
		writeAddress(&w, &token.serverAddresses[i])
	}

	w.bytes(token.clientToServerKey[:])
	w.bytes(token.serverToClientKey[:])
	w.bytes(token.userData[:])

	clear(buffer[w.pos:connectTokenPrivateBytes])
}

func (token *connectTokenPrivate) read(buffer []byte) error {
	if len(buffer) < connectTokenPrivateBytes {
		return errors.New("netcode: buffer too small for private connect token")
	}

	r := reader{buffer: buffer}

	token.clientID = r.uint64()
	token.timeoutSeconds = int32(r.uint32())
	token.numServerAddresses = int(int32(r.uint32()))

	if token.numServerAddresses <= 0 || token.numServerAddresses > MaxServersPerConnect {
		return fmt.Errorf("netcode: bad number of server addresses (%d)", token.numServerAddresses)
	}

	for i := 0; i < token.numServerAddresses; i++ {
		if err := readAddress(&r, &token.serverAddresses[i]); err != nil {
			return err
		}
	}

	r.bytes(token.clientToServerKey[:])
	r.bytes(token.serverToClientKey[:])
	r.bytes(token.userData[:])

	return nil
}

// connectTokenAdditionalData builds the associated data for private connect
// token encryption: version info, protocol id and expire timestamp.
func connectTokenAdditionalData(protocolID uint64, expireTimestamp uint64) [versionInfoBytes + 8 + 8]byte {
	var additional [versionInfoBytes + 8 + 8]byte
	w := writer{buffer: additional[:]}
	w.bytes(versionInfo[:])
	w.uint64(protocolID)
	w.uint64(expireTimestamp)
	return additional
}

// encryptConnectTokenPrivate encrypts the first 1024-16 bytes of buffer in
// place with XChaCha20-Poly1305, leaving the last 16 bytes to store the MAC.
func encryptConnectTokenPrivate(buffer []byte, protocolID uint64, expireTimestamp uint64, nonce []byte, key []byte) error {
	additional := connectTokenAdditionalData(protocolID, expireTimestamp)
	return encryptAEADBigNonce(buffer, connectTokenPrivateBytes-MacBytes, additional[:], nonce, key)
}

func decryptConnectTokenPrivate(buffer []byte, protocolID uint64, expireTimestamp uint64, nonce []byte, key []byte) error {
	additional := connectTokenAdditionalData(protocolID, expireTimestamp)
	return decryptAEADBigNonce(buffer, connectTokenPrivateBytes, additional[:], nonce, key)
}

// ----------------------------------------------------------------
// challenge token

// challengeToken stops clients with spoofed IP packet source addresses from
// connecting to servers.
type challengeToken struct {
	clientID uint64
	userData [UserDataBytes]byte
}

// write writes the challenge token to a fixed size buffer of
// challengeTokenBytes (300). Unused bytes are zero padded.
func (token *challengeToken) write(buffer []byte) {
	clear(buffer[:challengeTokenBytes])
	w := writer{buffer: buffer}
	w.uint64(token.clientID)
	w.bytes(token.userData[:])
}

func (token *challengeToken) read(buffer []byte) error {
	if len(buffer) < challengeTokenBytes {
		return errors.New("netcode: buffer too small for challenge token")
	}
	r := reader{buffer: buffer}
	token.clientID = r.uint64()
	r.bytes(token.userData[:])
	return nil
}

// encryptChallengeToken encrypts the first 300-16 bytes of buffer in place
// with ChaCha20-Poly1305, no associated data, and a nonce constructed from the
// challenge sequence number. The last 16 bytes store the MAC.
func encryptChallengeToken(buffer []byte, sequence uint64, key []byte) error {
	nonce := packetNonce(sequence)
	return encryptAEAD(buffer, challengeTokenBytes-MacBytes, nil, nonce[:], key)
}

func decryptChallengeToken(buffer []byte, sequence uint64, key []byte) error {
	nonce := packetNonce(sequence)
	return decryptAEAD(buffer, challengeTokenBytes, nil, nonce[:], key)
}

// ----------------------------------------------------------------
// public connect token

// connectToken is the public connect token passed to Client.Connect. It wraps
// the encrypted private connect token data together with everything the client
// needs to connect: server addresses, client and server keys, and timeouts.
type connectToken struct {
	protocolID         uint64
	createTimestamp    uint64
	expireTimestamp    uint64
	nonce              [connectTokenNonceBytes]byte
	privateData        [connectTokenPrivateBytes]byte
	timeoutSeconds     int32
	numServerAddresses int
	serverAddresses    [MaxServersPerConnect]Address
	clientToServerKey  [KeyBytes]byte
	serverToClientKey  [KeyBytes]byte
}

// write writes the connect token to a fixed size buffer of ConnectTokenBytes
// (2048). Unused bytes are zero padded.
func (token *connectToken) write(buffer []byte) {
	w := writer{buffer: buffer}

	w.bytes(versionInfo[:])
	w.uint64(token.protocolID)
	w.uint64(token.createTimestamp)
	w.uint64(token.expireTimestamp)
	w.bytes(token.nonce[:])
	w.bytes(token.privateData[:])
	w.uint32(uint32(token.timeoutSeconds))
	w.uint32(uint32(token.numServerAddresses))

	for i := 0; i < token.numServerAddresses; i++ {
		writeAddress(&w, &token.serverAddresses[i])
	}

	w.bytes(token.clientToServerKey[:])
	w.bytes(token.serverToClientKey[:])

	clear(buffer[w.pos:ConnectTokenBytes])
}

func (token *connectToken) read(buffer []byte) error {
	if len(buffer) != ConnectTokenBytes {
		printf(LogLevelError, "error: read connect data has bad buffer length (%d)\n", len(buffer))
		return errors.New("netcode: bad connect token buffer length")
	}

	r := reader{buffer: buffer}

	var packetVersionInfo [versionInfoBytes]byte
	r.bytes(packetVersionInfo[:])
	if packetVersionInfo != versionInfo {
		printf(LogLevelError, "error: read connect data has bad version info\n")
		return errors.New("netcode: bad connect token version info")
	}

	token.protocolID = r.uint64()
	token.createTimestamp = r.uint64()
	token.expireTimestamp = r.uint64()

	if token.createTimestamp > token.expireTimestamp {
		return errors.New("netcode: connect token expires before it was created")
	}

	r.bytes(token.nonce[:])
	r.bytes(token.privateData[:])

	token.timeoutSeconds = int32(r.uint32())
	token.numServerAddresses = int(int32(r.uint32()))

	if token.numServerAddresses <= 0 || token.numServerAddresses > MaxServersPerConnect {
		printf(LogLevelError, "error: read connect data has bad number of server addresses (%d)\n", token.numServerAddresses)
		return errors.New("netcode: bad number of server addresses")
	}

	for i := 0; i < token.numServerAddresses; i++ {
		if err := readAddress(&r, &token.serverAddresses[i]); err != nil {
			printf(LogLevelError, "error: read connect data has bad address type\n")
			return err
		}
	}

	r.bytes(token.clientToServerKey[:])
	r.bytes(token.serverToClientKey[:])

	return nil
}

// ----------------------------------------------------------------

// GenerateConnectToken generates a connect token for a client, exactly as the
// web backend would. Each entry of publicServerAddresses is the address the
// client connects to, with the corresponding entry of internalServerAddresses
// being the address the server sees itself as (often the same). Pass a
// negative expireSeconds or timeoutSeconds to disable expiry or timeout
// respectively (dev only). userData is up to 256 bytes of user defined data,
// and may be nil.
//
// The returned connect token is ConnectTokenBytes (2048 bytes) long.
func GenerateConnectToken(publicServerAddresses []string,
	internalServerAddresses []string,
	expireSeconds int,
	timeoutSeconds int,
	clientID uint64,
	protocolID uint64,
	privateKey []byte,
	userData []byte) ([]byte, error) {

	numServerAddresses := len(publicServerAddresses)
	if numServerAddresses <= 0 || numServerAddresses > MaxServersPerConnect {
		return nil, fmt.Errorf("netcode: number of server addresses must be in [1,%d]", MaxServersPerConnect)
	}
	if len(internalServerAddresses) != numServerAddresses {
		return nil, errors.New("netcode: must pass the same number of public and internal server addresses")
	}
	if len(privateKey) != KeyBytes {
		return nil, fmt.Errorf("netcode: private key must be %d bytes", KeyBytes)
	}
	if len(userData) > UserDataBytes {
		return nil, fmt.Errorf("netcode: user data must be at most %d bytes", UserDataBytes)
	}

	// parse public server addresses

	parsedPublicServerAddresses := make([]Address, numServerAddresses)
	for i := 0; i < numServerAddresses; i++ {
		address, err := ParseAddress(publicServerAddresses[i])
		if err != nil {
			return nil, err
		}
		parsedPublicServerAddresses[i] = address
	}

	// parse internal server addresses

	parsedInternalServerAddresses := make([]Address, numServerAddresses)
	for i := 0; i < numServerAddresses; i++ {
		address, err := ParseAddress(internalServerAddresses[i])
		if err != nil {
			return nil, err
		}
		parsedInternalServerAddresses[i] = address
	}

	// generate a connect token

	nonce := generateNonce()

	tokenPrivate := generateConnectTokenPrivate(clientID, int32(timeoutSeconds), parsedInternalServerAddresses, userData)

	// write it to a buffer

	var privateData [connectTokenPrivateBytes]byte
	tokenPrivate.write(privateData[:])

	// encrypt the buffer

	createTimestamp := uint64(time.Now().Unix())
	expireTimestamp := uint64(0xFFFFFFFFFFFFFFFF)
	if expireSeconds >= 0 {
		expireTimestamp = createTimestamp + uint64(expireSeconds)
	}

	if err := encryptConnectTokenPrivate(privateData[:], protocolID, expireTimestamp, nonce[:], privateKey); err != nil {
		return nil, err
	}

	// wrap a connect token around the private connect token data

	token := connectToken{
		protocolID:         protocolID,
		createTimestamp:    createTimestamp,
		expireTimestamp:    expireTimestamp,
		nonce:              nonce,
		privateData:        privateData,
		timeoutSeconds:     int32(timeoutSeconds),
		numServerAddresses: numServerAddresses,
		clientToServerKey:  tokenPrivate.clientToServerKey,
		serverToClientKey:  tokenPrivate.serverToClientKey,
	}
	copy(token.serverAddresses[:], parsedPublicServerAddresses)

	// write the connect token to the output buffer

	outputBuffer := make([]byte, ConnectTokenBytes)
	token.write(outputBuffer)

	return outputBuffer, nil
}
