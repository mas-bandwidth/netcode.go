//go:build darwin || linux || freebsd || openbsd || netbsd

package netcode

import (
	"net"

	"golang.org/x/sys/unix"
)

// enablePacketTagging sets the DSCP codepoint to expedited forwarding (46) so
// routers and Wi-Fi access points prioritize these packets as low latency.
func enablePacketTagging(conn *net.UDPConn, ipv6 bool) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockoptErr error
	err = rawConn.Control(func(fd uintptr) {
		const tos = 46
		if ipv6 {
			sockoptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos)
		} else {
			sockoptErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
		}
	})
	if err != nil {
		return err
	}
	return sockoptErr
}
