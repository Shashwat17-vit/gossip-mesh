// Package transport opens the UDP sockets a node needs.
//
// It is small, but it is where the genuinely awkward networking details live, so
// it is worth reading closely. A node uses THREE sockets for TWO jobs:
//
//	discovery in   multicast listener, fixed well-known port, inbound HELLO
//	discovery out  connected sender aimed at the multicast group
//	peer traffic   unicast socket on an ephemeral port, CHAT/HAVE/WANT
//
// Why discovery and peer traffic cannot share one socket, which is the least
// obvious decision in the whole project:
//
// Discovery needs a FIXED port, because a peer that has never heard of us cannot
// guess a random one. But a fixed port breaks the "two nodes on one laptop"
// case: to bind a port twice you need SO_REUSEADDR, and with two sockets sharing
// a port, an incoming UNICAST datagram is delivered to only one of them, chosen
// by the kernel. Multicast is different — it is delivered to every socket bound
// to the port. So multicast on a fixed shared port works for discovery, while
// unicast replies need a port of their own per process.
//
// Splitting the two also means each socket only ever receives a known subset of
// message types, which keeps the parsing side simpler.
package transport

import (
	"fmt"
	"net"
	"strings"
)

// GroupAddr validates a multicast group and pairs it with the discovery port.
func GroupAddr(group string, port int) (*net.UDPAddr, error) {
	ip := net.ParseIP(group)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("transport: %q is not an IPv4 address", group)
	}
	if !ip.IsMulticast() {
		return nil, fmt.Errorf("transport: %s is not a multicast address (try 239.x.y.z)", group)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("transport: discovery port %d out of range", port)
	}
	return &net.UDPAddr{IP: ip.To4(), Port: port}, nil
}

// ListenUnicast opens the socket used for peer-to-peer traffic. Port 0 asks the
// OS for any free port, which is the normal case: peers learn the real port from
// the HELLO beacon, so there is nothing for the user to configure or collide on.
func ListenUnicast(port int) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, fmt.Errorf("transport: listen on udp/%d: %w", port, err)
	}
	return conn, nil
}

// ListenMulticast joins the discovery group on a specific interface.
//
// net.ListenMulticastUDP does two things for us: it issues the IGMP join so the
// network stack (and a well-behaved switch) starts delivering group traffic, and
// it sets SO_REUSEADDR, which is what lets several gossipmesh processes on one
// machine share the discovery port.
//
// One consequence worth knowing: the socket is bound to 0.0.0.0, not to the
// group address, so it also receives ordinary unicast traffic aimed at this
// port. That is one of the reasons every frame starts with a magic number.
func ListenMulticast(iface *net.Interface, group *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := net.ListenMulticastUDP("udp4", iface, group)
	if err != nil {
		return nil, fmt.Errorf("transport: join %s on %s: %w (a firewall may be blocking it; --peer host:port is the fallback)", group, iface.Name, err)
	}
	return conn, nil
}

// MulticastSender returns a connected socket for outbound beacons.
//
// Binding the local address to a specific interface IP is how the outgoing
// interface gets chosen without reaching for platform-specific socket options:
// otherwise the routing table decides, and on a machine with Wi-Fi plus VPN plus
// Hyper-V adapters it frequently decides wrong.
func MulticastSender(localIP net.IP, group *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: localIP}, group)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s from %s: %w", group, localIP, err)
	}
	return conn, nil
}

// PickInterface chooses which network interface to use for discovery, and
// returns it together with its IPv4 address.
//
// This exists because a typical laptop has many interfaces — Wi-Fi, Ethernet,
// loopback, plus virtual ones from Hyper-V, WSL, VirtualBox or a VPN — and
// multicast is joined per interface. Guessing wrong means two nodes on the same
// Wi-Fi never see each other, with no error to explain why. Hence: prefer a
// real, up, multicast-capable interface holding a private LAN address, and let
// the user override with --iface when the guess is wrong.
func PickInterface(name string) (*net.Interface, net.IP, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, nil, fmt.Errorf("transport: interface %q: %w (available: %s)", name, err, strings.Join(usableNames(), ", "))
		}
		ip, err := ipv4Of(iface)
		if err != nil {
			return nil, nil, err
		}
		return iface, ip, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("transport: list interfaces: %w", err)
	}

	var fallbackIface *net.Interface
	var fallbackIP net.IP
	for i := range ifaces {
		iface := &ifaces[i]
		if !usable(iface) {
			continue
		}
		ip, err := ipv4Of(iface)
		if err != nil {
			continue
		}
		// A private address is a strong hint that this is the real LAN
		// interface rather than a virtual adapter with a link-local address.
		if ip.IsPrivate() {
			return iface, ip, nil
		}
		if fallbackIface == nil {
			fallbackIface, fallbackIP = iface, ip
		}
	}
	if fallbackIface != nil {
		return fallbackIface, fallbackIP, nil
	}
	return nil, nil, fmt.Errorf("transport: no usable IPv4 multicast interface found (try --iface with one of: %s)", strings.Join(usableNames(), ", "))
}

func usable(iface *net.Interface) bool {
	return iface.Flags&net.FlagUp != 0 &&
		iface.Flags&net.FlagMulticast != 0 &&
		iface.Flags&net.FlagLoopback == 0
}

func ipv4Of(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("transport: addresses of %s: %w", iface.Name, err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("transport: %s has no IPv4 address", iface.Name)
}

// usableNames is only used to make error messages actionable.
func usableNames() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for i := range ifaces {
		if iface := &ifaces[i]; usable(iface) {
			if _, err := ipv4Of(iface); err == nil {
				names = append(names, iface.Name)
			}
		}
	}
	return names
}
