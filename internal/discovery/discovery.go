// Package discovery tracks who is currently on the network.
//
// It is deliberately just the data structure: the beacon sending and HELLO
// parsing live in the node package, next to the other packet handling, because
// splitting "send a beacon" from "receive a beacon" across two packages makes
// the protocol harder to follow, not easier. What lives here is the table those
// handlers write into, and the liveness rule that empties it.
//
// The liveness rule is the whole idea of soft-state discovery: nobody ever sends
// a "goodbye". A peer exists while its beacons keep arriving and stops existing
// when they stop. That means a laptop closed mid-conversation, a process killed
// with -9, and someone walking out of Wi-Fi range are all the same event and
// need no special handling — which is exactly the property you want in a network
// with no coordinator to notify.
package discovery

import (
	"net"
	"sync"
	"time"

	"gossipmesh/internal/identity"
)

// Peer is one other node, as learned from its HELLO beacon.
//
// Name is chosen by the peer and therefore untrusted: two peers can claim the
// same nickname. FP cannot be forged in the same way, because it is derived from
// the signing key that authenticated the beacon, which is why the UI always
// shows them together.
//
// BoxPub is the only key kept, because encrypting to a peer is the only thing a
// peer record is needed for. Their signing key is not stored, since every message
// carries the key that signed it and the fingerprint is derived from that.
type Peer struct {
	FP       identity.Fingerprint
	Name     string
	BoxPub   [32]byte
	Addr     *net.UDPAddr // unicast address for chat and gossip
	LastSeen time.Time
}

// Table is the set of live peers, keyed by fingerprint.
//
// Keying by fingerprint rather than by IP is what makes the mesh survive a
// changing network: a peer that moves to a new DHCP lease is still the same
// identity, and its entry is simply updated with the new address.
type Table struct {
	// RWMutex rather than Mutex because the read/write ratio is lopsided: the
	// table is read on every single send and fanout, and written only when a
	// beacon arrives every couple of seconds.
	mu    sync.RWMutex
	peers map[identity.Fingerprint]Peer
}

func NewTable() *Table {
	return &Table{peers: make(map[identity.Fingerprint]Peer)}
}

// Upsert records a beacon, and reports whether this peer is newly discovered so
// the caller can announce it to the user exactly once rather than every 2
// seconds.
func (t *Table) Upsert(peer Peer) (isNew bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, existed := t.peers[peer.FP]
	peer.LastSeen = time.Now()
	t.peers[peer.FP] = peer
	return !existed
}

// Lookup finds a peer by fingerprint.
func (t *Table) Lookup(fp identity.Fingerprint) (Peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peer, ok := t.peers[fp]
	return peer, ok
}

// Snapshot returns a copy of the peer list.
//
// Returning copies rather than pointers is what keeps callers honest: a fanout
// loop can iterate for as long as it likes without holding the lock, and cannot
// accidentally observe a peer mutating underneath it. Peer is a handful of
// bytes, so copying a dozen of them is free compared to a packet send.
func (t *Table) Snapshot() []Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peers := make([]Peer, 0, len(t.peers))
	for _, peer := range t.peers {
		peers = append(peers, peer)
	}
	return peers
}

// Expire removes peers that have gone quiet for longer than ttl, returning them
// so the caller can report the departures.
func (t *Table) Expire(ttl time.Duration) []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-ttl)
	var gone []Peer
	for fp, peer := range t.peers {
		if peer.LastSeen.Before(cutoff) {
			gone = append(gone, peer)
			delete(t.peers, fp)
		}
	}
	return gone
}

// Len is the current number of live peers.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.peers)
}
