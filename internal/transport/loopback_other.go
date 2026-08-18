//go:build !windows

package transport

import "net"

// enableMulticastLoopback is a no-op away from Windows. There, IP_MULTICAST_LOOP
// decides whether a socket's own outbound packets come back to it, and this
// socket never sends; the sender socket keeps the default, which is on, so other
// processes on the same host still receive our beacons.
func enableMulticastLoopback(*net.UDPConn) error { return nil }
