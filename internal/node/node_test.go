package node

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder collects a node's event stream so a failing test can show the
// verbose protocol trace instead of just "it did not work".
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) watch(n *Node) {
	go func() {
		for line := range n.Events() {
			r.mu.Lock()
			r.lines = append(r.lines, line)
			r.mu.Unlock()
		}
	}()
}

func (r *recorder) dump(t *testing.T, who string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	t.Logf("--- %s ---\n%s", who, strings.Join(r.lines, "\n"))
}

func (r *recorder) contains(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range r.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

// pair starts two real nodes and returns them with their event logs. Everything
// is torn down (and the verbose traces printed) when the test ends.
//
// bobCfg is a function so it can see the port the OS actually gave alice. No
// test pins a port: a hard-coded one collides with any real node the developer
// happens to be running, which shows up as a confusing skip rather than an
// honest result.
func pair(t *testing.T, aliceCfg Config, bobCfg func(alicePort uint16) Config) (*Node, *Node, *recorder, *recorder) {
	t.Helper()

	alice, err := New(aliceCfg)
	if err != nil {
		t.Skipf("cannot open sockets on this host: %v", err)
	}
	bob, err := New(bobCfg(alice.dataPort))
	if err != nil {
		alice.Close()
		t.Skipf("cannot open sockets on this host: %v", err)
	}

	aliceLog, bobLog := &recorder{}, &recorder{}
	aliceLog.watch(alice)
	bobLog.watch(bob)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		alice.Close()
		bob.Close()
		alice.Wait()
		bob.Wait()
		if t.Failed() {
			aliceLog.dump(t, alice.id.Name)
			bobLog.dump(t, bob.id.Name)
		}
	})

	alice.Start(ctx)
	bob.Start(ctx)
	return alice, bob, aliceLog, bobLog
}

// exchange is the assertion both transport paths share: once two nodes know each
// other, a message typed on one is decrypted and displayed on the other.
func exchange(t *testing.T, from, to *Node, toLog *recorder, text string) {
	t.Helper()

	if err := from.Compose(text); err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { return to.store.Len() > 0 }) {
		t.Fatalf("%s never received the message", to.id.Name)
	}

	entries := to.store.Recent(10)
	if len(entries) != 1 {
		t.Fatalf("%s holds %d messages, want 1", to.id.Name, len(entries))
	}
	got := entries[0]
	if !got.Readable {
		t.Fatalf("%s could not decrypt a message it was a recipient of", to.id.Name)
	}
	if got.Text != text {
		t.Errorf("text = %q, want %q", got.Text, text)
	}
	if got.SenderFP != from.id.Fingerprint() {
		t.Errorf("sender = %s, want %s", got.SenderFP, from.id.Fingerprint())
	}
	if !toLog.contains(text) {
		t.Errorf("%s never displayed the message to the user", to.id.Name)
	}
}

// The unicast path, which needs no multicast at all: one node pins its port and
// the other is pointed straight at it with --peer. This is the fallback for
// networks (and firewalls) that drop multicast, so it must always work.
func TestTwoNodesPairViaSeedPeer(t *testing.T) {
	dir := t.TempDir()

	alice, bob, _, bobLog := pair(t,
		Config{Name: "alice", DataDir: dir, Trace: true},
		func(alicePort uint16) Config {
			return Config{Name: "bob", DataDir: dir, Seed: fmt.Sprintf("127.0.0.1:%d", alicePort), Trace: true}
		},
	)

	// Bob's beacon reaches alice directly; alice answers to the address it came
	// from, so both sides end up knowing each other from one unicast packet.
	if !waitFor(10*time.Second, func() bool {
		return alice.peers.Len() > 0 && bob.peers.Len() > 0
	}) {
		t.Fatalf("seeded nodes did not pair: alice sees %d peers, bob sees %d", alice.peers.Len(), bob.peers.Len())
	}

	exchange(t, alice, bob, bobLog, "ping from alice over unicast")
}

// Peers must not time out while they are still there.
//
// The bug this pins down: a node reached over unicast used to hear our HELLO
// exactly once, when it first discovered us, because our beacon only went to the
// multicast group. On a network that blocks multicast, its entry for us then
// expired after peerTTL and it reported us offline while we were happily
// receiving its beacons. The beacon now also goes directly to known peers.
func TestPresenceSurvivesPeerTTL(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out peerTTL")
	}
	dir := t.TempDir()

	alice, bob, _, _ := pair(t,
		Config{Name: "alice", DataDir: dir},
		func(alicePort uint16) Config {
			return Config{Name: "bob", DataDir: dir, Seed: fmt.Sprintf("127.0.0.1:%d", alicePort)}
		},
	)

	if !waitFor(10*time.Second, func() bool {
		return alice.peers.Len() > 0 && bob.peers.Len() > 0
	}) {
		t.Fatal("seeded nodes did not pair")
	}

	time.Sleep(peerTTL + sweepInterval + time.Second)

	if alice.peers.Len() == 0 {
		t.Error("alice expired bob even though bob is still beaconing")
	}
	if bob.peers.Len() == 0 {
		t.Error("bob expired alice even though alice is still beaconing")
	}
}

// The zero-configuration path: no ports, no addresses, just multicast discovery.
//
// This depends on the host allowing inbound multicast, which a firewall or a
// public/guest network often does not. That is outside the program's control, so
// the test skips (with an explanation) rather than failing.
func TestTwoNodesDiscoverViaMulticast(t *testing.T) {
	dir := t.TempDir()

	alice, bob, _, bobLog := pair(t,
		Config{Name: "alice", DataDir: dir, Trace: true},
		func(uint16) Config { return Config{Name: "bob", DataDir: dir, Trace: true} },
	)

	if !waitFor(10*time.Second, func() bool {
		return alice.peers.Len() > 0 && bob.peers.Len() > 0
	}) {
		t.Skipf("multicast discovery is blocked on this host (%d inbound packets seen); "+
			"the unicast --peer path is covered by TestTwoNodesPairViaSeedPeer", alice.received.Load())
	}

	exchange(t, alice, bob, bobLog, "ping from alice over multicast")
}
