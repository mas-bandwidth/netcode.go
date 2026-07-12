package netcode

import (
	"errors"
	"fmt"
	"net"
)

const (
	clientSocketSndbufSize = 4 * 1024 * 1024
	clientSocketRcvbufSize = 4 * 1024 * 1024
	serverSocketSndbufSize = 4 * 1024 * 1024
	serverSocketRcvbufSize = 4 * 1024 * 1024

	// Received packets are buffered on a channel between the reader goroutine
	// and Update. If the channel fills up faster than Update drains it, further
	// packets are dropped, just as the OS drops packets when a socket buffer
	// overflows.
	socketPacketChannelSize = 1024
)

var packetTaggingEnabled bool

// EnablePacketTagging tags packets sent from sockets created after this call
// as low latency (DSCP EF) which can significantly reduce jitter on Wi-Fi
// routers. It is off by default because it doesn't play well with some older
// home routers.
func EnablePacketTagging() {
	packetTaggingEnabled = true
}

type receivedPacket struct {
	from Address
	data []byte
}

// socket wraps a UDP socket. The C implementation polls non-blocking sockets;
// here a reader goroutine blocks on the socket and buffers packets on a
// channel, which Update drains. The public API remains poll based and single
// threaded, matching the C library.
type socket struct {
	address Address // the address the socket is bound to, with the resolved port
	conn    *net.UDPConn
	packets chan receivedPacket
}

type socketHolder struct {
	ipv4 *socket
	ipv6 *socket
}

type socketError struct {
	bind bool // a bind failure (port in use), as opposed to any other socket error
	err  error
}

func (e *socketError) Error() string { return e.err.Error() }
func (e *socketError) Unwrap() error { return e.err }

func createSocket(address *Address, sendBufferSize int, receiveBufferSize int) (*socket, error) {
	network := "udp4"
	if address.Type == AddressIPv6 {
		network = "udp6" // Go sets IPV6_V6ONLY for the "udp6" network
	}

	conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(address.toNetip()))
	if err != nil {
		bind := isBindError(err)
		printf(LogLevelError, "error: failed to %s socket (%s)\n", map[bool]string{true: "bind", false: "create"}[bind], network)
		return nil, &socketError{bind: bind, err: err}
	}

	// increase socket send and receive buffer sizes. linux and windows clamp requests
	// that exceed the OS limit, but the BSDs reject them instead, so back off until accepted.

	{
		size := sendBufferSize
		for conn.SetWriteBuffer(size) != nil {
			size /= 2
			if size < 256*1024 {
				printf(LogLevelError, "error: failed to set socket send buffer size\n")
				_ = conn.Close()
				return nil, &socketError{err: errors.New("netcode: failed to set socket send buffer size")}
			}
		}
		if size != sendBufferSize {
			printf(LogLevelInfo, "socket send buffer size reduced from %d to %d\n", sendBufferSize, size)
		}
	}

	{
		size := receiveBufferSize
		for conn.SetReadBuffer(size) != nil {
			size /= 2
			if size < 256*1024 {
				printf(LogLevelError, "error: failed to set socket receive buffer size\n")
				_ = conn.Close()
				return nil, &socketError{err: errors.New("netcode: failed to set socket receive buffer size")}
			}
		}
		if size != receiveBufferSize {
			printf(LogLevelInfo, "socket receive buffer size reduced from %d to %d\n", receiveBufferSize, size)
		}
	}

	// tag packets as low latency

	if packetTaggingEnabled {
		if err := enablePacketTagging(conn, address.Type == AddressIPv6); err != nil {
			printf(LogLevelError, "error: failed to enable packet tagging (%s)\n", network)
			_ = conn.Close()
			return nil, &socketError{err: fmt.Errorf("netcode: failed to enable packet tagging: %w", err)}
		}
	}

	s := &socket{
		address: *address,
		conn:    conn,
		packets: make(chan receivedPacket, socketPacketChannelSize),
	}

	// if bound to port 0 find the actual port we got

	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		s.address.Port = uint16(localAddr.Port)
	}

	go s.readLoop()

	return s, nil
}

func (s *socket) readLoop() {
	for {
		buffer := make([]byte, maxPacketBytes)
		bytes, from, err := s.conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			printf(LogLevelError, "error: socket receive failed with error %v\n", err)
			continue
		}
		if bytes <= 0 {
			continue
		}
		packet := receivedPacket{from: addressFromNetip(from.Addr(), from.Port()), data: buffer[:bytes]}
		select {
		case s.packets <- packet:
		default:
			// channel full: drop the packet
		}
	}
}

func (s *socket) sendPacket(to *Address, packetData []byte) {
	// UDP send is fire and forget: errors are deliberately ignored, matching
	// the C implementation
	_, _ = s.conn.WriteToUDPAddrPort(packetData, to.toNetip())
}

// receivePacket returns the next buffered packet, or false if none are pending.
// It never blocks.
func (s *socket) receivePacket() (receivedPacket, bool) {
	select {
	case packet := <-s.packets:
		return packet, true
	default:
		return receivedPacket{}, false
	}
}

func (s *socket) destroy() {
	if s != nil && s.conn != nil {
		_ = s.conn.Close()
	}
}

func (h *socketHolder) destroy() {
	h.ipv4.destroy()
	h.ipv6.destroy()
}

// sendPacketToAddress is shared by the client and server send paths: dispatch a
// written packet to the network simulator, the send override, or the socket
// matching the destination address family.
func sendPacketToAddress(networkSimulator *NetworkSimulator,
	sendPacketOverride func(to *Address, packetData []byte),
	holder *socketHolder,
	from *Address,
	to *Address,
	packetData []byte) {

	if networkSimulator != nil {
		networkSimulator.SendPacket(from, to, packetData)
	} else if sendPacketOverride != nil {
		sendPacketOverride(to, packetData)
	} else if to.Type == AddressIPv4 && holder.ipv4 != nil {
		holder.ipv4.sendPacket(to, packetData)
	} else if to.Type == AddressIPv6 && holder.ipv6 != nil {
		holder.ipv6.sendPacket(to, packetData)
	}
}
