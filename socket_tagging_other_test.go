//go:build !(darwin || linux || freebsd || openbsd || netbsd)

package netcode

import (
	"net"
	"testing"
)

func checkPacketTaggingApplied(t *testing.T, conn *net.UDPConn, ipv6 bool) {
	t.Helper()
	// Packet tagging is not implemented on this platform, so there is no
	// socket option to inspect.
}
