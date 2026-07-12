//go:build !(darwin || linux || freebsd || openbsd || netbsd)

package netcode

import "net"

// Packet tagging is not implemented on this platform. On Windows the C
// implementation tags packets via the Qwave QoS2 API, which has no pure Go
// equivalent, so tagging is silently skipped.
func enablePacketTagging(conn *net.UDPConn, ipv6 bool) error {
	return nil
}
