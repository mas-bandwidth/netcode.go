package netcode

import (
	"errors"
	"time"
)

// Server create errors, returned from NewServer and NewServerDual. Bind
// failures are reported separately from other socket errors because a port
// already in use is the common operational failure for dedicated servers.
var (
	ErrServerParseAddressFailed     = errors.New("netcode: failed to parse server public address")
	ErrServerParseAddress2Failed    = errors.New("netcode: failed to parse server public address2")
	ErrServerCreateSocketIPv4Failed = errors.New("netcode: failed to create server ipv4 socket")
	ErrServerCreateSocketIPv6Failed = errors.New("netcode: failed to create server ipv6 socket")
	ErrServerBindSocketIPv4Failed   = errors.New("netcode: failed to bind server ipv4 socket")
	ErrServerBindSocketIPv6Failed   = errors.New("netcode: failed to bind server ipv6 socket")
)

// Server flags.
const (
	serverFlagIgnoreConnectionRequestPackets  = 1
	serverFlagIgnoreConnectionResponsePackets = 1 << 1
)

// ServerConfig configures a Server. At minimum set ProtocolID and PrivateKey.
type ServerConfig struct {
	// ProtocolID is a 64 bit value unique to this particular game/application.
	// Only clients with a connect token generated for the same protocol id can
	// connect.
	ProtocolID uint64

	// PrivateKey is shared between the web backend and the dedicated servers.
	// Do not share your private key with anybody, and especially, do not
	// include it in your client executable!
	PrivateKey [KeyBytes]byte

	// NetworkSimulator, if set, routes all packets through a network simulator
	// instead of real sockets.
	NetworkSimulator *NetworkSimulator

	// ConnectDisconnectCallback, if set, is called when a client connects to
	// or disconnects from the server. During a disconnect it fires before the
	// client slot is reset, so the slot can still be queried from inside the
	// callback.
	ConnectDisconnectCallback func(clientIndex int, connected bool)

	// SendLoopbackPacketCallback is called to deliver packets sent to a client
	// in loopback mode. See Server.ConnectLoopbackClient.
	SendLoopbackPacketCallback func(clientIndex int, packetData []byte, packetSequence uint64)

	// OverrideSendAndReceive replaces socket send and receive with the
	// SendPacketOverride and ReceivePacketOverride callbacks. No sockets are
	// created.
	OverrideSendAndReceive bool
	SendPacketOverride     func(to *Address, packetData []byte)
	ReceivePacketOverride  func() (packetData []byte, from Address, ok bool)
}

const serverMaxReceivePackets = 64 * MaxClients

// Server is the dedicated server side of the netcode protocol. It manages a
// set of client slots, where each slot from [0,maxClients-1] represents room
// for one connected client.
//
// A server is not safe for concurrent use: call all methods from the same
// goroutine, and drive it by calling Update regularly (for example, 60 times
// per second).
type Server struct {
	config                      ServerConfig
	socketHolder                socketHolder
	address                     Address
	address2                    Address
	flags                       uint32
	time                        float64
	running                     bool
	maxClients                  int
	numConnectedClients         int
	globalSequence              uint64
	challengeSequence           uint64
	challengeKey                [KeyBytes]byte
	clientConnected             [MaxClients]bool
	clientTimeout               [MaxClients]int32
	clientLoopback              [MaxClients]bool
	clientConfirmed             [MaxClients]bool
	clientDisconnectReason      [MaxClients]int
	clientEncryptionIndex       [MaxClients]int
	clientID                    [MaxClients]uint64
	clientSequence              [MaxClients]uint64
	clientLastPacketSendTime    [MaxClients]float64
	clientLastPacketReceiveTime [MaxClients]float64
	clientUserData              [MaxClients][UserDataBytes]byte
	clientReplayProtection      [MaxClients]replayProtection
	clientPacketQueue           [MaxClients]packetQueue
	clientAddress               [MaxClients]Address
	connectTokenEntries         [maxConnectTokenEntries]connectTokenEntry
	encryptionManager           encryptionManager
}

func serverCreateSocket(address *Address, config *ServerConfig) (*socket, error) {
	if config.NetworkSimulator == nil && !config.OverrideSendAndReceive {
		s, err := createSocket(address, serverSocketSndbufSize, serverSocketRcvbufSize)
		if err != nil {
			// report bind failures separately: a port already in use is the common
			// operational failure for dedicated servers, and callers want to react
			// to it differently than to a socket that could not be created at all

			var sockErr *socketError
			bind := errors.As(err, &sockErr) && sockErr.bind

			if address.Type == AddressIPv6 {
				if bind {
					return nil, ErrServerBindSocketIPv6Failed
				}
				return nil, ErrServerCreateSocketIPv6Failed
			}
			if bind {
				return nil, ErrServerBindSocketIPv4Failed
			}
			return nil, ErrServerCreateSocketIPv4Failed
		}
		return s, nil
	}
	return nil, nil
}

// NewServerDual creates a server with two public addresses, one IPv4 and one
// IPv6, so clients can connect over either protocol. time is the current time
// in seconds, from any base you like; pass the same time base to Update.
func NewServerDual(serverAddress1String string, serverAddress2String string, config *ServerConfig, time float64) (*Server, error) {
	// tolerate a nil config: it's an inconvenience, not a crash
	var configCopy ServerConfig
	if config != nil {
		configCopy = *config
	}
	config = &configCopy

	serverAddress1, err := ParseAddress(serverAddress1String)
	if err != nil {
		printf(LogLevelError, "error: failed to parse server public address\n")
		return nil, ErrServerParseAddressFailed
	}

	var serverAddress2 Address
	if serverAddress2String != "" {
		serverAddress2, err = ParseAddress(serverAddress2String)
		if err != nil {
			printf(LogLevelError, "error: failed to parse server public address2\n")
			return nil, ErrServerParseAddress2Failed
		}
	}

	var socketIPv4 *socket
	var socketIPv6 *socket

	if serverAddress1.Type == AddressIPv4 || serverAddress2.Type == AddressIPv4 {
		bindAddress := Address{Type: AddressIPv4}
		if serverAddress1.Type == AddressIPv4 {
			bindAddress.Port = serverAddress1.Port
		} else {
			bindAddress.Port = serverAddress2.Port
		}
		socketIPv4, err = serverCreateSocket(&bindAddress, config)
		if err != nil {
			return nil, err
		}
	}

	if serverAddress1.Type == AddressIPv6 || serverAddress2.Type == AddressIPv6 {
		bindAddress := Address{Type: AddressIPv6}
		if serverAddress1.Type == AddressIPv6 {
			bindAddress.Port = serverAddress1.Port
		} else {
			bindAddress.Port = serverAddress2.Port
		}
		socketIPv6, err = serverCreateSocket(&bindAddress, config)
		if err != nil {
			socketIPv4.destroy()
			return nil, err
		}
	}

	if config.NetworkSimulator == nil {
		printf(LogLevelInfo, "server listening on %s\n", serverAddress1String)
	} else {
		printf(LogLevelInfo, "server listening on %s (network simulator)\n", serverAddress1String)
	}

	server := &Server{
		config:         *config,
		address:        serverAddress1,
		address2:       serverAddress2,
		time:           time,
		globalSequence: 1 << 63,
	}
	server.socketHolder.ipv4 = socketIPv4
	server.socketHolder.ipv6 = socketIPv6

	for i := 0; i < MaxClients; i++ {
		server.clientEncryptionIndex[i] = -1
	}

	connectTokenEntriesReset(&server.connectTokenEntries)

	server.encryptionManager.reset()

	for i := 0; i < MaxClients; i++ {
		server.clientReplayProtection[i].reset()
	}

	return server, nil
}

// NewServer creates a server with a single public address, e.g.
// "127.0.0.1:40000". The public address must match an address in the connect
// tokens clients connect with.
func NewServer(serverAddressString string, config *ServerConfig, time float64) (*Server, error) {
	return NewServerDual(serverAddressString, "", config, time)
}

// Close stops the server, disconnecting any connected clients, and releases
// its sockets.
func (server *Server) Close() {
	server.Stop()
	server.socketHolder.destroy()
}

// Start starts the server with the given number of client slots, in
// [1,MaxClients]. If the server is already running it is stopped and
// restarted.
func (server *Server) Start(maxClients int) {
	// the per-client arrays are sized MaxClients. an out of range value must not get through

	if maxClients <= 0 || maxClients > MaxClients {
		printf(LogLevelError, "error: max clients must be in [1,%d], got %d\n", MaxClients, maxClients)
		return
	}

	if server.running {
		server.Stop()
	}

	printf(LogLevelInfo, "server started with %d client slots\n", maxClients)

	server.running = true
	server.maxClients = maxClients
	server.numConnectedClients = 0
	// global packets (challenge, denied) encrypt with the same per-token server-to-client
	// keys as per-client packets, whose sequences start at zero, so the global sequence lives
	// in the top half of the sequence space to keep AEAD nonces disjoint under a shared key.
	// Stop() also resets it, so it must be re-seeded on every Start(), not just in NewServer,
	// or a stopped-and-restarted server would reuse nonces.
	server.globalSequence = 1 << 63
	server.challengeSequence = 0
	RandomBytes(server.challengeKey[:])

	for i := 0; i < server.maxClients; i++ {
		server.clientPacketQueue[i].clear()
	}

	for i := 0; i < MaxClients; i++ {
		server.clientDisconnectReason[i] = DisconnectReasonNone
	}
}

func (server *Server) sendGlobalPacket(p packet, to *Address, packetKey []byte) {
	var packetData [maxPacketBytes]byte

	packetBytes := writePacket(p, packetData[:], server.globalSequence, packetKey, server.config.ProtocolID)
	if packetBytes == 0 {
		return
	}

	var sendPacketOverride func(to *Address, packetData []byte)
	if server.config.OverrideSendAndReceive {
		sendPacketOverride = server.config.SendPacketOverride
	}

	sendPacketToAddress(server.config.NetworkSimulator,
		sendPacketOverride,
		&server.socketHolder,
		&server.address,
		to,
		packetData[:packetBytes])

	server.globalSequence++
}

func (server *Server) sendClientPacket(p packet, clientIndex int) {
	if !server.encryptionManager.touch(server.clientEncryptionIndex[clientIndex], &server.clientAddress[clientIndex], server.time) {
		printf(LogLevelError, "error: encryption mapping is out of date for client %d\n", clientIndex)
		return
	}

	packetKey := server.encryptionManager.getSendKey(server.clientEncryptionIndex[clientIndex])

	var packetData [maxPacketBytes]byte

	packetBytes := writePacket(p, packetData[:], server.clientSequence[clientIndex], packetKey, server.config.ProtocolID)
	if packetBytes == 0 {
		return
	}

	var sendPacketOverride func(to *Address, packetData []byte)
	if server.config.OverrideSendAndReceive {
		sendPacketOverride = server.config.SendPacketOverride
	}

	sendPacketToAddress(server.config.NetworkSimulator,
		sendPacketOverride,
		&server.socketHolder,
		&server.address,
		&server.clientAddress[clientIndex],
		packetData[:packetBytes])

	server.clientSequence[clientIndex]++

	server.clientLastPacketSendTime[clientIndex] = server.time
}

func (server *Server) resetClientSlot(clientIndex int) {
	server.clientPacketQueue[clientIndex].clear()

	server.clientConnected[clientIndex] = false
	server.clientLoopback[clientIndex] = false
	server.clientConfirmed[clientIndex] = false
	server.clientID[clientIndex] = 0
	server.clientSequence[clientIndex] = 0
	server.clientLastPacketSendTime[clientIndex] = 0.0
	server.clientLastPacketReceiveTime[clientIndex] = 0.0
	server.clientAddress[clientIndex] = Address{}
	server.clientEncryptionIndex[clientIndex] = -1
	server.clientUserData[clientIndex] = [UserDataBytes]byte{}

	server.numConnectedClients--
}

func (server *Server) disconnectClientInternal(clientIndex int, sendDisconnectPackets bool, disconnectReason int) {
	printf(LogLevelInfo, "server disconnected client %d\n", clientIndex)

	// record why before the callback fires, so the reason can be queried from inside the callback

	server.clientDisconnectReason[clientIndex] = disconnectReason

	if server.config.ConnectDisconnectCallback != nil {
		server.config.ConnectDisconnectCallback(clientIndex, false)
	}

	if sendDisconnectPackets {
		printf(LogLevelDebug, "server sent disconnect packets to client %d\n", clientIndex)

		for i := 0; i < numDisconnectPackets; i++ {
			printf(LogLevelDebug, "server sent disconnect packet %d\n", i)
			server.sendClientPacket(&connectionDisconnect{}, clientIndex)
		}
	}

	server.clientReplayProtection[clientIndex].reset()

	server.encryptionManager.clientIndex[server.clientEncryptionIndex[clientIndex]] = -1

	server.encryptionManager.removeEncryptionMapping(&server.clientAddress[clientIndex], server.time)

	server.resetClientSlot(clientIndex)
}

// DisconnectClient disconnects the client in the given slot, sending a number
// of redundant disconnect packets so the client finds out quickly instead of
// timing out.
func (server *Server) DisconnectClient(clientIndex int) {
	if !server.running {
		return
	}

	if clientIndex < 0 || clientIndex >= server.maxClients {
		return
	}

	if !server.clientConnected[clientIndex] {
		return
	}

	if server.clientLoopback[clientIndex] {
		return
	}

	server.disconnectClientInternal(clientIndex, true, DisconnectReasonServerDisconnect)
}

// DisconnectAllClients disconnects all connected clients. Loopback clients are
// left alone; use DisconnectLoopbackClient for those.
func (server *Server) DisconnectAllClients() {
	if !server.running {
		return
	}

	for i := 0; i < server.maxClients; i++ {
		if server.clientConnected[i] && !server.clientLoopback[i] {
			server.disconnectClientInternal(i, true, DisconnectReasonServerDisconnect)
		}
	}
}

// Stop stops the server, disconnecting all clients. The server can be started
// again with Start.
func (server *Server) Stop() {
	if !server.running {
		return
	}

	server.DisconnectAllClients()

	// loopback clients are not disconnected above, but they must not survive a server stop

	for i := 0; i < server.maxClients; i++ {
		if server.clientConnected[i] && server.clientLoopback[i] {
			server.DisconnectLoopbackClient(i)
		}
	}

	server.running = false
	server.maxClients = 0
	server.numConnectedClients = 0

	// never let the global sequence return to zero (see Start): zero would collide AEAD
	// nonces with per-client packets under the shared key on a restart.
	server.globalSequence = 1 << 63
	server.challengeSequence = 0
	server.challengeKey = [KeyBytes]byte{}

	connectTokenEntriesReset(&server.connectTokenEntries)

	server.encryptionManager.reset()

	printf(LogLevelInfo, "server stopped\n")
}

func (server *Server) findClientIndexByID(clientID uint64) int {
	for i := 0; i < server.maxClients; i++ {
		if server.clientConnected[i] && server.clientID[i] == clientID {
			return i
		}
	}
	return -1
}

func (server *Server) findClientIndexByAddress(address *Address) int {
	for i := 0; i < server.maxClients; i++ {
		if server.clientConnected[i] && server.clientAddress[i].Equal(*address) {
			return i
		}
	}
	return -1
}

func (server *Server) processConnectionRequestPacket(from *Address, packet *connectionRequest) {
	var connectTokenPrivate connectTokenPrivate
	if connectTokenPrivate.read(packet.connectTokenData[:]) != nil {
		printf(LogLevelDebug, "server ignored connection request. failed to read connect token\n")
		return
	}

	foundServerAddress := false
	for i := 0; i < connectTokenPrivate.numServerAddresses; i++ {
		if server.address.Equal(connectTokenPrivate.serverAddresses[i]) {
			foundServerAddress = true
		}
		if server.address2.Type != AddressNone && server.address2.Equal(connectTokenPrivate.serverAddresses[i]) {
			foundServerAddress = true
		}
	}
	if !foundServerAddress {
		printf(LogLevelDebug, "server ignored connection request. server address not in connect token whitelist\n")
		return
	}

	if server.findClientIndexByAddress(from) != -1 {
		printf(LogLevelDebug, "server ignored connection request. a client with this address is already connected\n")
		return
	}

	if server.findClientIndexByID(connectTokenPrivate.clientID) != -1 {
		printf(LogLevelDebug, "server ignored connection request. a client with this id is already connected\n")
		return
	}

	if !connectTokenEntriesFindOrAdd(&server.connectTokenEntries,
		from,
		packet.connectTokenData[connectTokenPrivateBytes-MacBytes:],
		server.time) {
		printf(LogLevelDebug, "server ignored connection request. connect token has already been used\n")
		return
	}

	if server.numConnectedClients == server.maxClients {
		printf(LogLevelDebug, "server denied connection request. server is full\n")
		server.sendGlobalPacket(&connectionDenied{}, from, connectTokenPrivate.serverToClientKey[:])
		return
	}

	expireTime := -1.0
	if connectTokenPrivate.timeoutSeconds >= 0 {
		expireTime = server.time + float64(connectTokenPrivate.timeoutSeconds)
	}

	if !server.encryptionManager.addEncryptionMapping(from,
		connectTokenPrivate.serverToClientKey[:],
		connectTokenPrivate.clientToServerKey[:],
		server.time,
		expireTime,
		connectTokenPrivate.timeoutSeconds) {
		printf(LogLevelDebug, "server ignored connection request. failed to add encryption mapping\n")
		return
	}

	challengeToken := challengeToken{
		clientID: connectTokenPrivate.clientID,
		userData: connectTokenPrivate.userData,
	}

	challengePacket := &connectionChallenge{
		challengeTokenSequence: server.challengeSequence,
	}
	challengeToken.write(challengePacket.challengeTokenData[:])
	if encryptChallengeToken(challengePacket.challengeTokenData[:], server.challengeSequence, server.challengeKey[:]) != nil {
		printf(LogLevelDebug, "server ignored connection request. failed to encrypt challenge token\n")
		return
	}

	server.challengeSequence++

	printf(LogLevelDebug, "server sent connection challenge packet\n")

	server.sendGlobalPacket(challengePacket, from, connectTokenPrivate.serverToClientKey[:])
}

func (server *Server) findFreeClientIndex() int {
	for i := 0; i < server.maxClients; i++ {
		if !server.clientConnected[i] {
			return i
		}
	}
	return -1
}

func (server *Server) connectClient(clientIndex int, address *Address, clientID uint64, encryptionIndex int, timeoutSeconds int32, userData []byte) {
	server.numConnectedClients++

	server.encryptionManager.setExpireTime(encryptionIndex, -1.0)

	server.encryptionManager.clientIndex[encryptionIndex] = clientIndex

	server.clientConnected[clientIndex] = true
	server.clientTimeout[clientIndex] = timeoutSeconds
	server.clientEncryptionIndex[clientIndex] = encryptionIndex
	server.clientID[clientIndex] = clientID
	server.clientSequence[clientIndex] = 0
	server.clientAddress[clientIndex] = *address
	server.clientDisconnectReason[clientIndex] = DisconnectReasonNone

	server.clientLastPacketSendTime[clientIndex] = server.time
	server.clientLastPacketReceiveTime[clientIndex] = server.time
	copy(server.clientUserData[clientIndex][:], userData)

	printf(LogLevelInfo, "server accepted client %s %.16x in slot %d\n", address.String(), clientID, clientIndex)

	packet := &connectionKeepAlive{
		clientIndex: int32(clientIndex),
		maxClients:  int32(server.maxClients),
	}
	server.sendClientPacket(packet, clientIndex)

	if server.config.ConnectDisconnectCallback != nil {
		server.config.ConnectDisconnectCallback(clientIndex, true)
	}
}

func (server *Server) processConnectionResponsePacket(from *Address, packet *connectionResponse, encryptionIndex int) {
	if decryptChallengeToken(packet.challengeTokenData[:], packet.challengeTokenSequence, server.challengeKey[:]) != nil {
		printf(LogLevelDebug, "server ignored connection response. failed to decrypt challenge token\n")
		return
	}

	var challengeToken challengeToken
	if challengeToken.read(packet.challengeTokenData[:]) != nil {
		printf(LogLevelDebug, "server ignored connection response. failed to read challenge token\n")
		return
	}

	packetSendKey := server.encryptionManager.getSendKey(encryptionIndex)

	if packetSendKey == nil {
		printf(LogLevelDebug, "server ignored connection response. no packet send key\n")
		return
	}

	if server.findClientIndexByAddress(from) != -1 {
		printf(LogLevelDebug, "server ignored connection response. a client with this address is already connected\n")
		return
	}

	if server.findClientIndexByID(challengeToken.clientID) != -1 {
		printf(LogLevelDebug, "server ignored connection response. a client with this id is already connected\n")
		return
	}

	if server.numConnectedClients == server.maxClients {
		printf(LogLevelDebug, "server denied connection response. server is full\n")
		server.sendGlobalPacket(&connectionDenied{}, from, packetSendKey)
		return
	}

	clientIndex := server.findFreeClientIndex()

	timeoutSeconds := server.encryptionManager.getTimeout(encryptionIndex)

	server.connectClient(clientIndex, from, challengeToken.clientID, encryptionIndex, timeoutSeconds, challengeToken.userData[:])
}

func (server *Server) processPacketInternal(from *Address, p packet, sequence uint64, encryptionIndex int, clientIndex int) {
	switch t := p.(type) {
	case *connectionRequest:
		if server.flags&serverFlagIgnoreConnectionRequestPackets == 0 {
			printf(LogLevelDebug, "server received connection request from %s\n", from.String())
			server.processConnectionRequestPacket(from, t)
		}

	case *connectionResponse:
		if server.flags&serverFlagIgnoreConnectionResponsePackets == 0 {
			printf(LogLevelDebug, "server received connection response from %s\n", from.String())
			server.processConnectionResponsePacket(from, t, encryptionIndex)
		}

	case *connectionKeepAlive:
		if clientIndex != -1 {
			printf(LogLevelDebug, "server received connection keep alive packet from client %d\n", clientIndex)
			server.clientLastPacketReceiveTime[clientIndex] = server.time
			if !server.clientConfirmed[clientIndex] {
				printf(LogLevelDebug, "server confirmed connection with client %d\n", clientIndex)
				server.clientConfirmed[clientIndex] = true
			}
		}

	case *connectionPayload:
		if clientIndex != -1 {
			printf(LogLevelDebug, "server received connection payload packet from client %d\n", clientIndex)
			server.clientLastPacketReceiveTime[clientIndex] = server.time
			if !server.clientConfirmed[clientIndex] {
				printf(LogLevelDebug, "server confirmed connection with client %d\n", clientIndex)
				server.clientConfirmed[clientIndex] = true
			}
			server.clientPacketQueue[clientIndex].push(t, sequence)
		}

	case *connectionDisconnect:
		if clientIndex != -1 {
			printf(LogLevelDebug, "server received disconnect packet from client %d\n", clientIndex)
			server.disconnectClientInternal(clientIndex, false, DisconnectReasonClientDisconnect)
		}
	}
}

// ProcessPacket processes a raw packet received from the given address, as if
// it had arrived on one of the server's sockets. This is useful together with
// ServerConfig.OverrideSendAndReceive to drive the server with your own
// transport.
func (server *Server) ProcessPacket(from *Address, packetData []byte) {
	allowedPackets := serverAllowedPackets()

	currentTimestamp := uint64(time.Now().Unix())

	server.readAndProcessPacket(from, packetData, currentTimestamp, &allowedPackets)
}

func serverAllowedPackets() [connectionNumPackets]bool {
	allowedPackets := [connectionNumPackets]bool{}
	allowedPackets[connectionRequestPacket] = true
	allowedPackets[connectionResponsePacket] = true
	allowedPackets[connectionKeepAlivePacket] = true
	allowedPackets[connectionPayloadPacket] = true
	allowedPackets[connectionDisconnectPacket] = true
	return allowedPackets
}

func (server *Server) readAndProcessPacket(from *Address, packetData []byte, currentTimestamp uint64, allowedPackets *[connectionNumPackets]bool) {
	if !server.running {
		return
	}

	if len(packetData) <= 1 {
		return
	}

	var sequence uint64

	var encryptionIndex int
	clientIndex := server.findClientIndexByAddress(from)
	if clientIndex != -1 {
		encryptionIndex = server.clientEncryptionIndex[clientIndex]
	} else {
		encryptionIndex = server.encryptionManager.findEncryptionMapping(from, server.time)
	}

	readPacketKey := server.encryptionManager.getReceiveKey(encryptionIndex)

	if readPacketKey == nil && packetData[0] != 0 {
		printf(LogLevelDebug, "server could not process packet because no encryption mapping exists for %s\n", from.String())
		return
	}

	var replay *replayProtection
	if clientIndex != -1 {
		replay = &server.clientReplayProtection[clientIndex]
	}

	packet := readPacket(packetData,
		&sequence,
		readPacketKey,
		server.config.ProtocolID,
		currentTimestamp,
		server.config.PrivateKey[:],
		allowedPackets,
		replay)

	if packet == nil {
		return
	}

	server.processPacketInternal(from, packet, sequence, encryptionIndex, clientIndex)
}

func (server *Server) receivePackets() {
	allowedPackets := serverAllowedPackets()

	currentTimestamp := uint64(time.Now().Unix())

	if server.config.NetworkSimulator == nil {
		// process packets received from sockets

		for {
			var from Address
			var packetData []byte

			if server.config.OverrideSendAndReceive {
				data, overrideFrom, ok := server.config.ReceivePacketOverride()
				if !ok {
					break
				}
				from = overrideFrom
				packetData = data
			} else {
				var packet receivedPacket
				var ok bool
				if server.socketHolder.ipv4 != nil {
					packet, ok = server.socketHolder.ipv4.receivePacket()
				}
				if !ok && server.socketHolder.ipv6 != nil {
					packet, ok = server.socketHolder.ipv6.receivePacket()
				}
				if !ok {
					break
				}
				from = packet.from
				packetData = packet.data
			}

			server.readAndProcessPacket(&from, packetData, currentTimestamp, &allowedPackets)
		}
	} else {
		// process packets received from network simulator

		packetData, from := server.config.NetworkSimulator.ReceivePackets(&server.address, serverMaxReceivePackets)

		for i := range packetData {
			server.readAndProcessPacket(&from[i], packetData[i], currentTimestamp, &allowedPackets)
		}
	}
}

func (server *Server) sendPackets() {
	if !server.running {
		return
	}

	for i := 0; i < server.maxClients; i++ {
		if server.clientConnected[i] && !server.clientLoopback[i] &&
			server.clientLastPacketSendTime[i]+(1.0/packetSendRate) <= server.time {
			printf(LogLevelDebug, "server sent connection keep alive packet to client %d\n", i)
			packet := &connectionKeepAlive{
				clientIndex: int32(i),
				maxClients:  int32(server.maxClients),
			}
			server.sendClientPacket(packet, i)
		}
	}
}

func (server *Server) checkForTimeouts() {
	if !server.running {
		return
	}

	for i := 0; i < server.maxClients; i++ {
		if !server.clientConnected[i] {
			continue
		}

		if server.clientTimeout[i] <= 0 {
			continue
		}

		if server.clientLoopback[i] {
			continue
		}

		if server.time-server.clientLastPacketReceiveTime[i] >= 1.0 {
			printf(LogLevelDebug, "server has not received a packet from client %d for %.2f seconds\n", i, server.time-server.clientLastPacketReceiveTime[i])
		}

		if server.clientLastPacketReceiveTime[i]+float64(server.clientTimeout[i]) <= server.time {
			printf(LogLevelInfo, "server timed out client %d\n", i)
			server.disconnectClientInternal(i, false, DisconnectReasonTimedOut)
		}
	}
}

// ClientConnected reports whether a client is connected in the given slot.
func (server *Server) ClientConnected(clientIndex int) bool {
	if !server.running {
		return false
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return false
	}
	return server.clientConnected[clientIndex]
}

// ClientDisconnectReason returns why the client in the given slot was last
// disconnected: one of the DisconnectReason constants. It is reset to
// DisconnectReasonNone when the server starts and when a new client connects
// to the slot, and is recorded before the ConnectDisconnectCallback fires, so
// it can be queried from inside that callback.
func (server *Server) ClientDisconnectReason(clientIndex int) int {
	if !server.running {
		return DisconnectReasonNone
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return DisconnectReasonNone
	}
	return server.clientDisconnectReason[clientIndex]
}

// ClientID returns the client id of the client in the given slot, or zero if
// no client is connected there.
func (server *Server) ClientID(clientIndex int) uint64 {
	if !server.running {
		return 0
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return 0
	}
	return server.clientID[clientIndex]
}

// ClientAddress returns the address of the client in the given slot.
func (server *Server) ClientAddress(clientIndex int) Address {
	if !server.running {
		return Address{}
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return Address{}
	}
	return server.clientAddress[clientIndex]
}

// NextPacketSequence returns the sequence number of the next packet the server
// will send to the given client.
func (server *Server) NextPacketSequence(clientIndex int) uint64 {
	if !server.running {
		return 0
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return 0
	}
	if !server.clientConnected[clientIndex] {
		return 0
	}
	return server.clientSequence[clientIndex]
}

// SendPacket sends a payload packet to the client in the given slot. The
// packet must be between 1 and MaxPacketSize bytes. Packets are unreliable
// and unordered.
func (server *Server) SendPacket(clientIndex int, packetData []byte) {
	// zero byte payloads are not valid on the wire and would silently vanish at the receiver

	if len(packetData) <= 0 || len(packetData) > MaxPacketSize {
		printf(LogLevelError, "error: payload packet size is out of range (%d)\n", len(packetData))
		return
	}

	if !server.running {
		return
	}

	if clientIndex < 0 || clientIndex >= server.maxClients {
		return
	}

	if !server.clientConnected[clientIndex] {
		return
	}

	if !server.clientLoopback[clientIndex] {
		packet := &connectionPayload{payloadData: packetData}

		// while the client is not confirmed, prefix each payload packet with a keep-alive
		// packet, so the client learns its client index and max clients as early as possible

		if !server.clientConfirmed[clientIndex] {
			keepAlivePacket := &connectionKeepAlive{
				clientIndex: int32(clientIndex),
				maxClients:  int32(server.maxClients),
			}
			server.sendClientPacket(keepAlivePacket, clientIndex)
		}

		server.sendClientPacket(packet, clientIndex)
	} else {
		server.config.SendLoopbackPacketCallback(clientIndex, packetData, server.clientSequence[clientIndex])
		server.clientSequence[clientIndex]++
		server.clientLastPacketSendTime[clientIndex] = server.time
	}
}

// ReceivePacket pops the next payload packet received from the client in the
// given slot, returning the payload and the sequence number of the packet it
// arrived in. Returns nil when no packets remain. Call it in a loop after
// Update until it returns nil.
func (server *Server) ReceivePacket(clientIndex int) ([]byte, uint64) {
	if !server.running {
		return nil, 0
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return nil, 0
	}
	if !server.clientConnected[clientIndex] {
		return nil, 0
	}
	packet, sequence := server.clientPacketQueue[clientIndex].pop()
	if packet == nil {
		return nil, 0
	}
	return packet.payloadData, sequence
}

// NumConnectedClients returns the number of clients currently connected.
func (server *Server) NumConnectedClients() int {
	return server.numConnectedClients
}

// ClientUserData returns the user data from the connect token of the client in
// the given slot. It is UserDataBytes long.
func (server *Server) ClientUserData(clientIndex int) []byte {
	if !server.running {
		return nil
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return nil
	}
	return server.clientUserData[clientIndex][:]
}

// Running reports whether the server has been started.
func (server *Server) Running() bool {
	return server.running
}

// MaxClients returns the number of client slots the server was started with.
func (server *Server) MaxClients() int {
	return server.maxClients
}

// Update advances the server to the given time: it receives and processes
// packets, sends keep-alive packets, and times out clients. Call it regularly,
// for example 60 times per second.
func (server *Server) Update(time float64) {
	server.time = time
	server.receivePackets()
	server.sendPackets()
	server.checkForTimeouts()
}

// ConnectLoopbackClient connects a client to the given slot in loopback mode.
// Packets for this client flow through the SendLoopbackPacketCallback and
// ProcessLoopbackPacket instead of the network. This is intended for a local
// player being hosted in the same process as the server, e.g. listen servers.
func (server *Server) ConnectLoopbackClient(clientIndex int, clientID uint64, userData []byte) {
	if !server.running {
		return
	}

	if clientIndex < 0 || clientIndex >= server.maxClients {
		return
	}

	if server.clientConnected[clientIndex] {
		return
	}

	server.numConnectedClients++

	server.clientLoopback[clientIndex] = true
	server.clientConnected[clientIndex] = true
	server.clientConfirmed[clientIndex] = true
	server.clientEncryptionIndex[clientIndex] = -1
	server.clientID[clientIndex] = clientID
	server.clientSequence[clientIndex] = 0
	server.clientDisconnectReason[clientIndex] = DisconnectReasonNone
	server.clientAddress[clientIndex] = Address{}
	server.clientLastPacketSendTime[clientIndex] = server.time
	server.clientLastPacketReceiveTime[clientIndex] = server.time

	server.clientUserData[clientIndex] = [UserDataBytes]byte{}
	copy(server.clientUserData[clientIndex][:], userData)

	printf(LogLevelInfo, "server connected loopback client %.16x in slot %d\n", clientID, clientIndex)

	if server.config.ConnectDisconnectCallback != nil {
		server.config.ConnectDisconnectCallback(clientIndex, true)
	}
}

// DisconnectLoopbackClient disconnects the loopback client in the given slot.
func (server *Server) DisconnectLoopbackClient(clientIndex int) {
	if !server.running {
		return
	}

	if clientIndex < 0 || clientIndex >= server.maxClients {
		return
	}

	if !server.clientConnected[clientIndex] || !server.clientLoopback[clientIndex] {
		return
	}

	printf(LogLevelInfo, "server disconnected loopback client %d\n", clientIndex)

	server.clientDisconnectReason[clientIndex] = DisconnectReasonServerDisconnect

	if server.config.ConnectDisconnectCallback != nil {
		server.config.ConnectDisconnectCallback(clientIndex, false)
	}

	server.resetClientSlot(clientIndex)
}

// ClientLoopback reports whether the client in the given slot is in loopback
// mode.
func (server *Server) ClientLoopback(clientIndex int) bool {
	if !server.running {
		return false
	}
	if clientIndex < 0 || clientIndex >= server.maxClients {
		return false
	}
	return server.clientLoopback[clientIndex]
}

// ProcessLoopbackPacket delivers a payload packet from a loopback client to
// the server, as if it had been received over the network.
func (server *Server) ProcessLoopbackPacket(clientIndex int, packetData []byte, packetSequence uint64) {
	if !server.running {
		return
	}

	if clientIndex < 0 || clientIndex >= server.maxClients {
		return
	}

	if !server.clientConnected[clientIndex] || !server.clientLoopback[clientIndex] {
		return
	}

	if len(packetData) <= 0 || len(packetData) > MaxPacketSize {
		return
	}

	printf(LogLevelDebug, "server processing loopback packet from client %d\n", clientIndex)

	server.clientLastPacketReceiveTime[clientIndex] = server.time

	packet := &connectionPayload{payloadData: append([]byte(nil), packetData...)}
	server.clientPacketQueue[clientIndex].push(packet, packetSequence)
}

// Port returns the port the server socket is bound to.
func (server *Server) Port() uint16 {
	if server.address.Type == AddressIPv4 {
		if server.socketHolder.ipv4 != nil {
			return server.socketHolder.ipv4.address.Port
		}
	} else if server.socketHolder.ipv6 != nil {
		return server.socketHolder.ipv6.address.Port
	}
	return 0
}
