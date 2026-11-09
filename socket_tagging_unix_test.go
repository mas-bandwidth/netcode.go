//go:build darwin || linux || freebsd || openbsd || netbsd

package netcode

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

const testPacketTaggingCodepoint = 46

func checkPacketTaggingApplied(t *testing.T, conn *net.UDPConn, ipv6 bool) {
	t.Helper()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("get raw connection: %v", err)
	}

	var value int
	var sockoptErr error
	if err := rawConn.Control(func(fd uintptr) {
		if ipv6 {
			value, sockoptErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS)
		} else {
			value, sockoptErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
		}
	}); err != nil {
		t.Fatalf("control raw connection: %v", err)
	}
	if sockoptErr != nil {
		t.Fatalf("read packet tagging socket option: %v", sockoptErr)
	}
	if value != testPacketTaggingCodepoint {
		t.Fatalf("expected packet tagging codepoint %d, got %d", testPacketTaggingCodepoint, value)
	}
}
