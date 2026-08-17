package gossip

import (
	"fmt"
	"testing"

	"gossipmesh/internal/codec"
)

func entry(n byte) *Entry {
	e := &Entry{
		Raw:      []byte(fmt.Sprintf("frame-%d", n)),
		Sender:   "alice",
		TS:       int64(n),
		Text:     fmt.Sprintf("message %d", n),
		Readable: true,
	}
	e.ID[0] = n
	return e
}

// Dedup is what stops a message circulating forever in a mesh where every node
// forwards to every other node.
func TestAddDeduplicates(t *testing.T) {
	s := NewStore(10)

	if !s.Add(entry(1)) {
		t.Fatal("first Add reported the message as already known")
	}
	if s.Add(entry(1)) {
		t.Fatal("second Add of the same id reported it as new")
	}
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
	if !s.Has(entry(1).ID) {
		t.Error("Has = false for a stored message")
	}
	if s.Has(entry(2).ID) {
		t.Error("Has = true for a message never stored")
	}
}

// An unbounded store is a memory leak as soon as a peer decides to flood.
func TestStoreEvictsOldestOverCapacity(t *testing.T) {
	s := NewStore(3)
	for i := byte(1); i <= 5; i++ {
		s.Add(entry(i))
	}

	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3", s.Len())
	}
	if s.Has(entry(1).ID) || s.Has(entry(2).ID) {
		t.Error("the oldest messages were not evicted")
	}
	for i := byte(3); i <= 5; i++ {
		if !s.Has(entry(i).ID) {
			t.Errorf("message %d should still be held", i)
		}
	}
}

func TestDigestReturnsNewestFirstAndRespectsLimit(t *testing.T) {
	s := NewStore(10)
	for i := byte(1); i <= 5; i++ {
		s.Add(entry(i))
	}

	digest := s.Digest(2)
	if len(digest) != 2 {
		t.Fatalf("digest = %d ids, want 2", len(digest))
	}
	// The two newest, which is what a peer catching up actually needs.
	if digest[0][0] != 4 || digest[1][0] != 5 {
		t.Errorf("digest = %v, want the newest two (4, 5)", []byte{digest[0][0], digest[1][0]})
	}

	if got := len(s.Digest(100)); got != 5 {
		t.Errorf("Digest(100) = %d ids, want all 5", got)
	}
	if got := len(NewStore(4).Digest(10)); got != 0 {
		t.Errorf("empty store digest = %d ids, want 0", got)
	}
}

func TestMissingIsCappedToOneDatagram(t *testing.T) {
	s := NewStore(1000)

	ids := make([][codec.IDSize]byte, 0, codec.MaxIDsPerList+10)
	for i := 0; i < codec.MaxIDsPerList+10; i++ {
		var id [codec.IDSize]byte
		id[0], id[1] = byte(i), byte(i>>8)
		ids = append(ids, id)
	}

	if got := len(s.Missing(ids)); got != codec.MaxIDsPerList {
		t.Fatalf("Missing = %d ids, want it capped at %d", got, codec.MaxIDsPerList)
	}
}

// Anti-entropy in miniature: this is exactly the HAVE/WANT exchange two nodes
// perform over UDP, minus the sockets. If a datagram is lost, this is what
// repairs it.
func TestAntiEntropyConvergesTwoStores(t *testing.T) {
	alice, bob := NewStore(100), NewStore(100)

	for i := byte(1); i <= 4; i++ {
		alice.Add(entry(i))
	}
	bob.Add(entry(2)) // bob missed 1, 3 and 4

	// Alice announces what she holds (HAVE); Bob works out what he lacks (WANT).
	want := bob.Missing(alice.Digest(60))
	if len(want) != 3 {
		t.Fatalf("bob wants %d messages, expected 3", len(want))
	}

	// Alice answers with the original bytes of each requested message.
	for _, id := range want {
		raw, ok := alice.Raw(id)
		if !ok {
			t.Fatalf("alice cannot serve %x, which she advertised", id[:4])
		}
		restored := &Entry{ID: id, Raw: raw, Readable: false}
		if !bob.Add(restored) {
			t.Errorf("bob already had %x", id[:4])
		}
	}

	if bob.Len() != alice.Len() {
		t.Fatalf("bob holds %d messages, alice holds %d", bob.Len(), alice.Len())
	}
	if len(bob.Missing(alice.Digest(60))) != 0 {
		t.Error("the stores did not converge")
	}
}

func TestRawAndRecent(t *testing.T) {
	s := NewStore(10)
	s.Add(entry(1))
	s.Add(entry(2))

	raw, ok := s.Raw(entry(2).ID)
	if !ok || string(raw) != "frame-2" {
		t.Errorf("Raw = %q, %v", raw, ok)
	}
	if _, ok := s.Raw(entry(9).ID); ok {
		t.Error("Raw found a message that was never stored")
	}

	recent := s.Recent(5)
	if len(recent) != 2 || recent[0].TS != 1 || recent[1].TS != 2 {
		t.Errorf("Recent returned %d entries in the wrong order", len(recent))
	}
}
