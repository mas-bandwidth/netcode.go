package netcode

import (
	"errors"
	"time"
)

// Client create errors, returned from NewClient and NewClientDual.
var (
	ErrClientParseAddressFailed     = errors.New("netcode: failed to parse client address")
	ErrClientParseAddress2Failed    = errors.New("netcode: failed to parse client address2")
	ErrClientSimulatorRequiresPort  = errors.New("netcode: must bind to a specific port when using network simulator")
	ErrClientCreateSocketIPv4Failed = errors.New("netcode: failed to create client ipv4 socket")
	ErrClientCreateSocketIPv6Failed = errors.New("netcode: failed to create client ipv6 socket")
)

// ClientConfig configures a Client. The zero value gives working defaults:
// pass nil to NewClient to use it.
type ClientConfig struct {
	// NetworkSimulator, if set, routes all packets through a network simulator
	// instead of real sockets. The client must then bind to a specific port.
	NetworkSimulator *NetworkSimulator

	// StateChangeCallback, if set, is called whenever the client state changes.
	StateChangeCallback func(previousState int, currentState int)

	// SendLoopbackPacketCallback is called to deliver packets sent by a client
	// in loopback mode. See Client.ConnectLoopback.
	SendLoopbackPacketCallback func(clientIndex int, packetData []byte, packetSequence uint64)

	// OverrideSendAndReceive replaces socket send and receive with the
	// SendPacketOverride and ReceivePacketOverride callbacks. No sockets are
	// created.
	OverrideSendAndReceive bool
	SendPacketOverride     func(to *Address, packetData []byte)
	ReceivePacketOverride  func() (packetData []byte, from Address, ok bool)
}

// Client is the client side of a netcode connection.
//
// A client is not safe for concurrent use: call all methods from the same
// goroutine, and drive it by calling Update regularly (for example, 60 times
// per second).
type Client struct {
	config                 ClientConfig
	state                  int
	time                   float64
	connectStartTime       float64
	lastPacketSendTime     float64
	lastPacketReceiveTime  float64
	shouldDisconnect       bool
	shouldDisconnectState  int
	sequence               uint64
	clientIndex            int
	maxClients             int
	serverAddressIndex     int
	address                Address
	serverAddress          Address
	connectToken           connectToken
	socketHolder           socketHolder
	readPacketKey          [KeyBytes]byte
	writePacketKey         [KeyBytes]byte
	hasPacketKeys          bool
	replayProtection       replayProtection
	packetReceiveQueue     packetQueue
	challengeTokenSequence uint64
	challengeTokenData     [challengeTokenBytes]byte
	loopback               bool
}

func clientCreateSocket(address *Address, config *ClientConfig) (*socket, error) {
	if config.NetworkSimulator == nil {
		if !config.OverrideSendAndReceive {
			s, err := createSocket(address, clientSocketSndbufSize, clientSocketRcvbufSize)
			if err != nil {
				if address.Type == AddressIPv6 {
					return nil, ErrClientCreateSocketIPv6Failed
				}
				return nil, ErrClientCreateSocketIPv4Failed
			}
			return s, nil
		}
	} else if address.Port == 0 {
		printf(LogLevelError, "error: must bind to a specific port when using network simulator\n")
		return nil, ErrClientSimulatorRequiresPort
	}
	return nil, nil
}

// NewClientDual creates a client bound to two addresses, one IPv4 and one
// IPv6, so it can connect to servers over either protocol. Bind to port zero
// to get an ephemeral port. time is the current time in seconds, from any
// base you like; pass the same time base to Update.
func NewClientDual(address1String string, address2String string, config *ClientConfig, time float64) (*Client, error) {
	// tolerate a nil config: it's an inconvenience, not a crash
	var configCopy ClientConfig
	if config != nil {
		configCopy = *config
	}
	config = &configCopy

	address1, err := ParseAddress(address1String)
	if err != nil {
		printf(LogLevelError, "error: failed to parse client address\n")
		return nil, ErrClientParseAddressFailed
	}

	var address2 Address
	if address2String != "" {
		address2, err = ParseAddress(address2String)
		if err != nil {
			printf(LogLevelError, "error: failed to parse client address2\n")
			return nil, ErrClientParseAddress2Failed
		}
	}

	var socketIPv4 *socket
	var socketIPv6 *socket

	if address1.Type == AddressIPv4 || address2.Type == AddressIPv4 {
		bindAddress := &address1
		if address1.Type != AddressIPv4 {
			bindAddress = &address2
		}
		socketIPv4, err = clientCreateSocket(bindAddress, config)
		if err != nil {
			return nil, err
		}
	}

	if address1.Type == AddressIPv6 || address2.Type == AddressIPv6 {
		bindAddress := &address1
		if address1.Type != AddressIPv6 {
			bindAddress = &address2
		}
		socketIPv6, err = clientCreateSocket(bindAddress, config)
		if err != nil {
			socketIPv4.destroy()
			return nil, err
		}
	}

	var socketAddress Address
	if address1.Type == AddressIPv4 {
		if socketIPv4 != nil {
			socketAddress = socketIPv4.address
		}
	} else if socketIPv6 != nil {
		socketAddress = socketIPv6.address
	}

	if config.NetworkSimulator == nil {
		printf(LogLevelInfo, "client started on port %d\n", socketAddress.Port)
	} else {
		printf(LogLevelInfo, "client started on port %d (network simulator)\n", socketAddress.Port)
	}

	client := &Client{
		config:                *config,
		state:                 ClientStateDisconnected,
		time:                  time,
		lastPacketSendTime:    -1000.0,
		lastPacketReceiveTime: -1000.0,
		shouldDisconnectState: ClientStateDisconnected,
		address:               socketAddress,
	}
	client.socketHolder.ipv4 = socketIPv4
	client.socketHolder.ipv6 = socketIPv6
	if config.NetworkSimulator != nil {
		client.address = address1
	}

	client.replayProtection.reset()

	return client, nil
}

// NewClient creates a client bound to a single address. Bind to port zero to
// get an ephemeral port, e.g. "0.0.0.0:0" or "[::]:0".
func NewClient(address string, config *ClientConfig, time float64) (*Client, error) {
	return NewClientDual(address, "", config, time)
}

// Close disconnects the client (sending disconnect packets to the server if
// connected) and releases its sockets.
func (client *Client) Close() {
	if !client.loopback {
		client.Disconnect()
	} else {
		client.DisconnectLoopback()
	}
	client.socketHolder.destroy()
	client.packetReceiveQueue.clear()
}

func (client *Client) setState(clientState int) {
	printf(LogLevelDebug, "client changed state from '%s' to '%s'\n", ClientStateName(client.state), ClientStateName(clientState))
	if client.config.StateChangeCallback != nil {
		client.config.StateChangeCallback(client.state, clientState)
	}
	client.state = clientState
}

func (client *Client) resetBeforeNextConnect() {
	client.connectStartTime = client.time
	client.lastPacketSendTime = client.time - 1.0
	client.lastPacketReceiveTime = client.time
	client.shouldDisconnect = false
	client.shouldDisconnectState = ClientStateDisconnected
	client.challengeTokenSequence = 0
	client.challengeTokenData = [challengeTokenBytes]byte{}
	client.replayProtection.reset()
}

func (client *Client) resetConnectionData(clientState int) {
	client.sequence = 0
	client.loopback = false
	client.clientIndex = 0
	client.maxClients = 0
	client.connectStartTime = 0.0
	client.serverAddressIndex = 0
	client.serverAddress = Address{}
	client.connectToken = connectToken{}
	client.readPacketKey = [KeyBytes]byte{}
	client.writePacketKey = [KeyBytes]byte{}
	client.hasPacketKeys = false

	client.setState(clientState)

	client.resetBeforeNextConnect()

	client.packetReceiveQueue.clear()
}

// Connect takes a connect token generated by GenerateConnectToken (typically
// obtained from the web backend over HTTPS) and starts connecting to one of
// the server addresses in it. Progress is made in Update; poll State to see
// the result.
func (client *Client) Connect(connectTokenData []byte) {
	client.Disconnect()

	if client.connectToken.read(connectTokenData) != nil {
		client.setState(ClientStateInvalidConnectToken)
		return
	}

	client.serverAddressIndex = 0
	client.serverAddress = client.connectToken.serverAddresses[0]

	if client.connectToken.numServerAddresses == 1 {
		printf(LogLevelInfo, "client connecting to server %s\n", client.serverAddress.String())
	} else {
		printf(LogLevelInfo, "client connecting to server %s [%d/%d]\n", client.serverAddress.String(), client.serverAddressIndex+1, client.connectToken.numServerAddresses)
	}

	client.readPacketKey = client.connectToken.serverToClientKey
	client.writePacketKey = client.connectToken.clientToServerKey
	client.hasPacketKeys = true

	client.resetBeforeNextConnect()

	client.setState(ClientStateSendingConnectionRequest)
}

func (client *Client) processPacketInternal(from *Address, p packet, sequence uint64) {
	switch t := p.(type) {
	case *connectionDenied:
		if (client.state == ClientStateSendingConnectionRequest ||
			client.state == ClientStateSendingConnectionResponse) &&
			from.Equal(client.serverAddress) {
			client.shouldDisconnect = true
			client.shouldDisconnectState = ClientStateConnectionDenied
			client.lastPacketReceiveTime = client.time
		}

	case *connectionChallenge:
		if client.state == ClientStateSendingConnectionRequest && from.Equal(client.serverAddress) {
			printf(LogLevelDebug, "client received connection challenge packet from server\n")
			client.challengeTokenSequence = t.challengeTokenSequence
			client.challengeTokenData = t.challengeTokenData
			client.lastPacketReceiveTime = client.time
			client.setState(ClientStateSendingConnectionResponse)
		}

	case *connectionKeepAlive:
		if from.Equal(client.serverAddress) {
			switch client.state {
			case ClientStateConnected:
				printf(LogLevelDebug, "client received connection keep alive packet from server\n")
				client.lastPacketReceiveTime = client.time
			case ClientStateSendingConnectionResponse:
				printf(LogLevelDebug, "client received connection keep alive packet from server\n")
				client.lastPacketReceiveTime = client.time
				client.clientIndex = int(t.clientIndex)
				client.maxClients = int(t.maxClients)
				client.setState(ClientStateConnected)
				printf(LogLevelInfo, "client connected to server\n")
			}
		}

	case *connectionPayload:
		if client.state == ClientStateConnected && from.Equal(client.serverAddress) {
			printf(LogLevelDebug, "client received connection payload packet from server\n")
			client.packetReceiveQueue.push(t, sequence)
			client.lastPacketReceiveTime = client.time
		}

	case *connectionDisconnect:
		if client.state == ClientStateConnected && from.Equal(client.serverAddress) {
			printf(LogLevelDebug, "client received disconnect packet from server\n")
			client.shouldDisconnect = true
			client.shouldDisconnectState = ClientStateDisconnected
			client.lastPacketReceiveTime = client.time
		}
	}
}

// ProcessPacket processes a raw packet received from the given address, as if
// it had arrived on the client's socket. This is useful together with
// ClientConfig.OverrideSendAndReceive to drive the client with your own
// transport.
func (client *Client) ProcessPacket(from *Address, packetData []byte) {
	allowedPackets := [connectionNumPackets]bool{}
	allowedPackets[connectionDeniedPacket] = true
	allowedPackets[connectionChallengePacket] = true
	allowedPackets[connectionKeepAlivePacket] = true
	allowedPackets[connectionPayloadPacket] = true
	allowedPackets[connectionDisconnectPacket] = true

	currentTimestamp := uint64(time.Now().Unix())

	var readPacketKey []byte
	if client.hasPacketKeys {
		readPacketKey = client.readPacketKey[:]
	}

	var sequence uint64

	packet := readPacket(packetData,
		&sequence,
		readPacketKey,
		client.connectToken.protocolID,
		currentTimestamp,
		nil,
		&allowedPackets,
		&client.replayProtection)

	if packet == nil {
		return
	}

	client.processPacketInternal(from, packet, sequence)
}

func (client *Client) receivePackets() {
	if client.config.NetworkSimulator == nil {
		// process packets received from socket

		for {
			var from Address
			var packetData []byte

			if client.config.OverrideSendAndReceive {
				data, overrideFrom, ok := client.config.ReceivePacketOverride()
				if !ok {
					break
				}
				from = overrideFrom
				packetData = data
			} else {
				var s *socket
				switch client.serverAddress.Type {
				case AddressIPv4:
					s = client.socketHolder.ipv4
				case AddressIPv6:
					s = client.socketHolder.ipv6
				}
				if s == nil {
					break
				}
				packet, ok := s.receivePacket()
				if !ok {
					break
				}
				from = packet.from
				packetData = packet.data
			}

			client.ProcessPacket(&from, packetData)
		}
	} else {
		// process packets received from network simulator

		packetData, from := client.config.NetworkSimulator.ReceivePackets(&client.address, clientMaxReceivePackets)

		for i := range packetData {
			client.ProcessPacket(&from[i], packetData[i])
		}
	}
}

const clientMaxReceivePackets = 64

func (client *Client) sendPacketToServerInternal(p packet) {
	var packetData [maxPacketBytes]byte

	packetBytes := writePacket(p, packetData[:], client.sequence, client.writePacketKey[:], client.connectToken.protocolID)
	client.sequence++

	if packetBytes == 0 {
		return
	}

	var sendPacketOverride func(to *Address, packetData []byte)
	if client.config.OverrideSendAndReceive {
		sendPacketOverride = client.config.SendPacketOverride
	}

	sendPacketToAddress(client.config.NetworkSimulator,
		sendPacketOverride,
		&client.socketHolder,
		&client.address,
		&client.serverAddress,
		packetData[:packetBytes])

	client.lastPacketSendTime = client.time
}

func (client *Client) sendPackets() {
	switch client.state {
	case ClientStateSendingConnectionRequest:
		if client.lastPacketSendTime+(1.0/packetSendRate) >= client.time {
			return
		}

		printf(LogLevelDebug, "client sent connection request packet to server\n")

		packet := &connectionRequest{
			versionInfo:                 versionInfo,
			protocolID:                  client.connectToken.protocolID,
			connectTokenExpireTimestamp: client.connectToken.expireTimestamp,
			connectTokenNonce:           client.connectToken.nonce,
			connectTokenData:            client.connectToken.privateData,
		}
		client.sendPacketToServerInternal(packet)

	case ClientStateSendingConnectionResponse:
		if client.lastPacketSendTime+(1.0/packetSendRate) >= client.time {
			return
		}

		printf(LogLevelDebug, "client sent connection response packet to server\n")

		packet := &connectionResponse{
			challengeTokenSequence: client.challengeTokenSequence,
			challengeTokenData:     client.challengeTokenData,
		}
		client.sendPacketToServerInternal(packet)

	case ClientStateConnected:
		if client.lastPacketSendTime+(1.0/packetSendRate) >= client.time {
			return
		}

		printf(LogLevelDebug, "client sent connection keep alive packet to server\n")

		packet := &connectionKeepAlive{}
		client.sendPacketToServerInternal(packet)
	}
}

func (client *Client) connectToNextServer() bool {
	if client.serverAddressIndex+1 >= client.connectToken.numServerAddresses {
		printf(LogLevelDebug, "client has no more servers to connect to\n")
		return false
	}

	client.serverAddressIndex++
	client.serverAddress = client.connectToken.serverAddresses[client.serverAddressIndex]

	client.resetBeforeNextConnect()

	printf(LogLevelInfo, "client connecting to next server %s [%d/%d]\n",
		client.serverAddress.String(), client.serverAddressIndex+1, client.connectToken.numServerAddresses)

	client.setState(ClientStateSendingConnectionRequest)

	return true
}

// Update advances the client to the given time: it receives and processes
// packets, sends outgoing packets, and applies timeouts. Call it regularly,
// for example 60 times per second.
func (client *Client) Update(time float64) {
	client.time = time

	if client.loopback {
		return
	}

	client.receivePackets()

	client.sendPackets()

	if client.state > ClientStateDisconnected && client.state < ClientStateConnected {
		connectTokenExpireSeconds := client.connectToken.expireTimestamp - client.connectToken.createTimestamp
		if client.time-client.connectStartTime >= float64(connectTokenExpireSeconds) {
			printf(LogLevelInfo, "client connect failed. connect token expired\n")
			client.disconnectInternal(ClientStateConnectTokenExpired, false)
			return
		}
	}

	if client.shouldDisconnect {
		printf(LogLevelDebug, "client should disconnect -> %s\n", ClientStateName(client.shouldDisconnectState))
		if client.connectToNextServer() {
			return
		}
		client.disconnectInternal(client.shouldDisconnectState, false)
		return
	}

	switch client.state {
	case ClientStateSendingConnectionRequest:
		if client.connectToken.timeoutSeconds > 0 && client.lastPacketReceiveTime+float64(client.connectToken.timeoutSeconds) < time {
			printf(LogLevelInfo, "client connect failed. connection request timed out\n")
			if client.connectToNextServer() {
				return
			}
			client.disconnectInternal(ClientStateConnectionRequestTimedOut, false)
			return
		}

	case ClientStateSendingConnectionResponse:
		if client.connectToken.timeoutSeconds > 0 && client.lastPacketReceiveTime+float64(client.connectToken.timeoutSeconds) < time {
			printf(LogLevelInfo, "client connect failed. connection response timed out\n")
			if client.connectToNextServer() {
				return
			}
			client.disconnectInternal(ClientStateConnectionResponseTimedOut, false)
			return
		}

	case ClientStateConnected:
		if client.connectToken.timeoutSeconds > 0 && client.lastPacketReceiveTime+float64(client.connectToken.timeoutSeconds) < time {
			printf(LogLevelInfo, "client connection timed out\n")
			client.disconnectInternal(ClientStateConnectionTimedOut, false)
			return
		}
	}
}

// NextPacketSequence returns the sequence number of the next packet the client
// will send.
func (client *Client) NextPacketSequence() uint64 {
	return client.sequence
}

// SendPacket sends a payload packet to the server. The packet must be between
// 1 and MaxPacketSize bytes. Packets are unreliable and unordered. Does
// nothing unless the client is connected.
func (client *Client) SendPacket(packetData []byte) {
	// zero byte payloads are not valid on the wire and would silently vanish at the receiver

	if len(packetData) <= 0 || len(packetData) > MaxPacketSize {
		printf(LogLevelError, "error: payload packet size is out of range (%d)\n", len(packetData))
		return
	}

	if client.state != ClientStateConnected {
		return
	}

	if !client.loopback {
		packet := &connectionPayload{payloadData: packetData}
		client.sendPacketToServerInternal(packet)
	} else {
		client.config.SendLoopbackPacketCallback(client.clientIndex, packetData, client.sequence)
		client.sequence++
	}
}

// ReceivePacket pops the next payload packet received from the server off the
// receive queue, returning the payload and the sequence number of the packet
// it arrived in. Returns nil when no packets remain. Call it in a loop after
// Update until it returns nil.
func (client *Client) ReceivePacket() ([]byte, uint64) {
	packet, sequence := client.packetReceiveQueue.pop()
	if packet == nil {
		return nil, 0
	}
	return packet.payloadData, sequence
}

// Disconnect disconnects the client from the server, sending a number of
// redundant disconnect packets so the server can free the client slot quickly
// instead of timing out.
func (client *Client) Disconnect() {
	client.disconnectInternal(ClientStateDisconnected, true)
}

func (client *Client) disconnectInternal(destinationState int, sendDisconnectPackets bool) {
	if client.state <= ClientStateDisconnected || client.state == destinationState {
		return
	}

	printf(LogLevelInfo, "client disconnected\n")

	if !client.loopback && sendDisconnectPackets && client.state > ClientStateDisconnected {
		printf(LogLevelDebug, "client sent disconnect packets to server\n")

		for i := 0; i < numDisconnectPackets; i++ {
			printf(LogLevelDebug, "client sent disconnect packet %d\n", i)
			client.sendPacketToServerInternal(&connectionDisconnect{})
		}
	}

	client.resetConnectionData(destinationState)
}

// State returns the current client state, one of the ClientState constants.
func (client *Client) State() int {
	return client.state
}

// Index returns the client slot index assigned by the server, valid once
// connected.
func (client *Client) Index() int {
	return client.clientIndex
}

// MaxClients returns the maximum number of client slots on the server the
// client is connected to, valid once connected.
func (client *Client) MaxClients() int {
	return client.maxClients
}

// ConnectLoopback puts the client in loopback mode, connected to a local
// server in the same process without any packets going over the network. See
// Server.ConnectLoopbackClient for the server side.
func (client *Client) ConnectLoopback(clientIndex int, maxClients int) {
	printf(LogLevelInfo, "client connected to server via loopback as client %d\n", clientIndex)
	client.state = ClientStateConnected
	client.clientIndex = clientIndex
	client.maxClients = maxClients
	client.loopback = true
}

// DisconnectLoopback disconnects a client in loopback mode.
func (client *Client) DisconnectLoopback() {
	client.resetConnectionData(ClientStateDisconnected)
}

// Loopback reports whether the client is in loopback mode.
func (client *Client) Loopback() bool {
	return client.loopback
}

// ProcessLoopbackPacket delivers a payload packet to a client in loopback
// mode, as if it had been received from the server.
func (client *Client) ProcessLoopbackPacket(packetData []byte, packetSequence uint64) {
	if !client.loopback {
		return
	}

	if len(packetData) <= 0 || len(packetData) > MaxPacketSize {
		return
	}

	printf(LogLevelDebug, "client processing loopback packet from server\n")

	packet := &connectionPayload{payloadData: append([]byte(nil), packetData...)}
	client.packetReceiveQueue.push(packet, packetSequence)
}

// Port returns the port the client socket is bound to.
func (client *Client) Port() uint16 {
	if client.address.Type == AddressIPv4 {
		if client.socketHolder.ipv4 != nil {
			return client.socketHolder.ipv4.address.Port
		}
	} else if client.socketHolder.ipv6 != nil {
		return client.socketHolder.ipv6.address.Port
	}
	return 0
}

// ServerAddress returns the address of the server the client is connecting or
// connected to.
func (client *Client) ServerAddress() Address {
	return client.serverAddress
}
