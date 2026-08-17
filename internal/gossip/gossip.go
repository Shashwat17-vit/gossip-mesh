// Package gossip decides which messages this node holds, and which it is
// missing.
//
// It contains no networking at all. Everything here takes and returns plain
// data, which is what makes mesh convergence testable in-process: two Stores in
// a unit test can be reconciled with the same Digest/Missing calls that two
// machines use over UDP, with no sockets involved.
//
// The store does three jobs, and each one exists for a specific reason:
//
//	dedup     a mesh where everyone forwards to everyone would otherwise
//	          circulate a single message forever
//	repair    it can say what it holds (Digest) and what it lacks (Missing),
//	          which is how nodes reconcile after UDP drops a packet
//	bounding  it forgets old messages, because an append-only store is a
//	          memory leak the moment a hostile peer starts flooding
package gossip

import (
	"sync"

	"gossipmesh/internal/codec"
	"gossipmesh/internal/identity"
)

// Entry is one message as this node holds it.
//
// Raw is the original datagram, kept verbatim because relaying a re-encoded
// message would break its signature. Text is only populated when this node was
// one of the message's recipients — a node stores and forwards ciphertext it
// cannot read, which is what lets partly-connected peers act as carriers.
type Entry struct {
	ID       [codec.IDSize]byte
	Raw      []byte
	SenderFP identity.Fingerprint
	Sender   string
	TS       int64
	Text     string
	Readable bool
}

// Store is a bounded, ordered set of messages.
type Store struct {
	// One mutex, not two, and no sync.Map. The operations here are compound —
	// "check whether this is new, then insert it, then evict the oldest" — and
	// they must be atomic as a group, which is precisely what sync.Map cannot
	// give you.
	mu    sync.Mutex
	cap   int
	order [][codec.IDSize]byte // oldest first
	byID  map[[codec.IDSize]byte]*Entry
}

func NewStore(capacity int) *Store {
	if capacity < 1 {
		capacity = 1
	}
	return &Store{
		cap:   capacity,
		order: make([][codec.IDSize]byte, 0, capacity),
		byID:  make(map[[codec.IDSize]byte]*Entry, capacity),
	}
}

// Add stores a message, reporting false if it was already known.
//
// That boolean is the dedup decision, and the caller depends on it for more than
// tidiness: it is what stops a message being displayed twice and, more
// importantly, what stops it being relayed a second time.
func (s *Store) Add(e *Entry) (isNew bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byID[e.ID]; exists {
		return false
	}
	s.byID[e.ID] = e
	s.order = append(s.order, e.ID)

	// Evict oldest-first once we are over capacity. Note the consequence: an id
	// that has been evicted is no longer "seen", so a very old message could in
	// principle be re-displayed if a peer resent it. The 5-minute freshness
	// window enforced when verifying a message is what makes that a non-issue in
	// practice.
	for len(s.order) > s.cap {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.byID, oldest)
	}
	return true
}

// Has reports whether this message is already known. This is the seen-set check
// that terminates the gossip flood.
func (s *Store) Has(id [codec.IDSize]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.byID[id]
	return ok
}

// Raw returns the original datagram for a message, so it can be resent
// byte-for-byte in answer to a WANT.
func (s *Store) Raw(id [codec.IDSize]byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return entry.Raw, true
}

// Digest lists up to max of the most recently stored ids, newest-biased.
//
// Newest-first is the right bias for a chat application: a peer that has just
// joined or just recovered from packet loss almost always needs recent messages,
// and a digest has to fit in one datagram so it cannot list everything.
func (s *Store) Digest(max int) [][codec.IDSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if max > len(s.order) {
		max = len(s.order)
	}
	out := make([][codec.IDSize]byte, 0, max)
	for i := len(s.order) - max; i < len(s.order); i++ {
		out = append(out, s.order[i])
	}
	return out
}

// Missing returns the subset of ids this node does not hold: the answer to
// somebody else's Digest, and the body of the WANT we send back.
func (s *Store) Missing(ids [][codec.IDSize]byte) [][codec.IDSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	var missing [][codec.IDSize]byte
	for _, id := range ids {
		if _, ok := s.byID[id]; !ok {
			missing = append(missing, id)
			if len(missing) >= codec.MaxIDsPerList {
				break
			}
		}
	}
	return missing
}

// Recent returns up to n of the newest entries, oldest first, for /history.
func (s *Store) Recent(n int) []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n > len(s.order) {
		n = len(s.order)
	}
	out := make([]*Entry, 0, n)
	for i := len(s.order) - n; i < len(s.order); i++ {
		if entry, ok := s.byID[s.order[i]]; ok {
			out = append(out, entry)
		}
	}
	return out
}

// Len is how many messages are currently held.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.order)
}
