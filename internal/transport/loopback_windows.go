//go:build windows

package transport

import (
	"net"
	"syscall"
)

// enableMulticastLoopback turns IP_MULTICAST_LOOP back on for a multicast
// listener.
//
// net.ListenMulticastUDP switches that option off (net/udpsock_posix.go). On
// Unix the option governs the sending path, so disabling it on a socket that
// only ever receives changes nothing. Windows applies it to the receiving path
// instead, so leaving it off makes the socket discard every multicast packet
// sent from this machine — which means two nodes on one laptop never discover
// each other, with no error anywhere to explain why.
func enableMulticastLoopback(conn *net.UDPConn) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1)
	}); err != nil {
		return err
	}
	return setErr
}
