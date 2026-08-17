// Package node is the orchestrator: it owns the sockets, runs the goroutines,
// and is the only place that knows how all the other packages fit together.
//
// A running node is five goroutines around some shared state:
//
//	discovery reader  blocks on the multicast socket, learning who is online
//	peer reader       blocks on the unicast socket, receiving chat and gossip
//	ticker loop       beacons presence, runs anti-entropy, expires dead peers
//	writer            drains the send queue; the only code that writes packets
//	shutdown watcher  turns context cancellation into Close()
//
// Why one writer instead of "go conn.WriteTo(...)" at each call site: fanning
// out to N peers by spawning a goroutine per packet gives unbounded goroutines
// under load and no backpressure at all. A single writer draining a bounded
// channel makes the queue depth an observable number, degrades by dropping
// packets instead of exhausting memory, and means exactly one place touches the
// write side of each socket. Sending a UDP datagram is a microsecond-scale
// syscall, so one writer is nowhere near a bottleneck on a LAN.
package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gossipmesh/internal/codec"
	"gossipmesh/internal/crypto"
	"gossipmesh/internal/discovery"
	"gossipmesh/internal/gossip"
	"gossipmesh/internal/identity"
	"gossipmesh/internal/transport"
)

// Defaults for discovery. 239.255.42.99 is in the administratively scoped
// multicast range (239.0.0.0/8), which is the block reserved for private use
// inside an organisation — the multicast equivalent of 192.168.x.x. Routers do
// not forward it off the local network, which is exactly what we want.
const (
	DefaultGroup         = "239.255.42.99"
	DefaultDiscoveryPort = 9999
)

// Tuning. These are the numbers that define how the mesh behaves; they are
// gathered here rather than scattered through the code so they can be reasoned
// about together.
const (
	// beaconInterval is how often we announce ourselves. Frequent enough that a
	// new peer appears in a couple of seconds, rare enough to be invisible
	// traffic-wise.
	beaconInterval = 2 * time.Second

	// antiEntropyInterval is how often we tell peers what we hold, so that
	// anything lost to a dropped UDP packet gets repaired.
	antiEntropyInterval = 3 * time.Second

	// peerTTL is how long a peer survives without a beacon. Five missed
	// beacons, so ordinary packet loss does not make peers flicker in and out.
	peerTTL       = 10 * time.Second
	sweepInterval = 5 * time.Second

	// storeCapacity bounds message history. An append-only store is a memory
	// leak the moment a hostile peer decides to flood us.
	storeCapacity = 500

	// digestSize caps how many ids we advertise per HAVE, keeping it inside one
	// datagram (60 * 16 bytes + framing).
	digestSize = 60

	// wantReplyCap bounds how many messages we will resend for a single WANT.
	// A forged WANT is otherwise a traffic amplification lever: one small packet
	// asking for many large ones.
	wantReplyCap = 16

	// readBufferSize is comfortably larger than MaxDatagram so an oversized
	// packet is visibly wrong rather than silently truncated.
	readBufferSize = 2048

	sendQueueDepth  = 256
	eventQueueDepth = 256

	// isolationHintAfter is how long we wait before telling the user that
	// nothing at all is arriving. Beaconing into a void looks identical to
	// "nobody else is running yet", and the usual cause is a firewall dropping
	// inbound multicast, which is worth naming rather than leaving to be
	// guessed at.
	isolationHintAfter = 6 * time.Second
)

// Config is everything the CLI can set.
type Config struct {
	Name          string
	DataDir       string
	DataPort      int // 0 means "any free port"
	Iface         string
	Group         string
	DiscoveryPort int
	Seed          string // optional host:port, for when multicast is blocked
	Verbose       bool   // log real events: messages, relays, rejections
	Trace         bool   // also log every beacon and digest
}

// outbound is one queued datagram. A nil addr means "send to the multicast
// group" rather than to a specific peer.
//
// routine marks the clockwork traffic — beacons and digests — that happens
// whether or not anything is going on. It is logged only under --trace, because
// a couple of packets every two seconds per peer drowns out the events a reader
// actually cares about.
type outbound struct {
	frame   []byte
	addr    *net.UDPAddr
	what    string
	routine bool
}

// Node is one participant in the mesh.
type Node struct {
	cfg      Config
	id       *identity.Identity
	freshKey bool

	iface    *net.Interface
	localIP  net.IP
	group    *net.UDPAddr
	dataPort uint16
	seed     *net.UDPAddr

	// Two sockets, deliberately. See the comment on transport.ListenMulticast
	// for why discovery and peer traffic cannot share one.
	data     *net.UDPConn // unicast: chat, have, want
	mcastIn  *net.UDPConn // multicast listener: inbound hello
	mcastOut *net.UDPConn // multicast sender: outbound hello

	peers *discovery.Table
	store *gossip.Store

	sendq  chan outbound
	events chan string

	// received counts inbound datagrams. It is written by both read loops and
	// read by the ticker loop, so it is atomic; a plain int here would be a data
	// race that the race detector would (rightly) fail on.
	received atomic.Uint64
	started  time.Time
	hinted   bool // only touched by tickLoop

	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	waitOnce  sync.Once
}

// New loads this node's identity and opens its sockets, but starts nothing.
// Separating construction from Start means the CLI can print a banner (and fail
// with a clear error) before any goroutine exists.
func New(cfg Config) (*Node, error) {
	if cfg.DataDir == "" {
		cfg.DataDir = ".gossipmesh"
	}
	if cfg.Group == "" {
		cfg.Group = DefaultGroup
	}
	if cfg.DiscoveryPort == 0 {
		cfg.DiscoveryPort = DefaultDiscoveryPort
	}

	id, freshKey, err := identity.Load(cfg.DataDir, cfg.Name)
	if err != nil {
		return nil, err
	}

	iface, localIP, err := transport.PickInterface(cfg.Iface)
	if err != nil {
		return nil, err
	}
	group, err := transport.GroupAddr(cfg.Group, cfg.DiscoveryPort)
	if err != nil {
		return nil, err
	}

	var seed *net.UDPAddr
	if cfg.Seed != "" {
		if seed, err = net.ResolveUDPAddr("udp4", cfg.Seed); err != nil {
			return nil, fmt.Errorf("--peer %q: %w", cfg.Seed, err)
		}
	}

	data, err := transport.ListenUnicast(cfg.DataPort)
	if err != nil {
		return nil, err
	}
	mcastIn, err := transport.ListenMulticast(iface, group)
	if err != nil {
		data.Close()
		return nil, err
	}
	mcastOut, err := transport.MulticastSender(localIP, group)
	if err != nil {
		data.Close()
		mcastIn.Close()
		return nil, err
	}

	return &Node{
		cfg:      cfg,
		id:       id,
		freshKey: freshKey,
		iface:    iface,
		localIP:  localIP,
		group:    group,
		dataPort: uint16(data.LocalAddr().(*net.UDPAddr).Port),
		seed:     seed,
		data:     data,
		mcastIn:  mcastIn,
		mcastOut: mcastOut,
		peers:    discovery.NewTable(),
		store:    gossip.NewStore(storeCapacity),
		sendq:    make(chan outbound, sendQueueDepth),
		events:   make(chan string, eventQueueDepth),
		done:     make(chan struct{}),
	}, nil
}

// Start launches the node's goroutines. It returns immediately.
func (n *Node) Start(ctx context.Context) {
	n.started = time.Now()

	// Translate context cancellation into Close(). Close is what actually stops
	// the loops, so there is one shutdown path whether the trigger was Ctrl+C
	// or the user typing /quit. The second case in the select is what stops this
	// goroutine leaking when shutdown came from Close() rather than the context.
	n.spawn(func() {
		select {
		case <-ctx.Done():
			n.Close()
		case <-n.done:
		}
	})

	n.spawn(n.writeLoop)
	n.spawn(func() { n.readLoop(n.mcastIn, "discovery") })
	n.spawn(func() { n.readLoop(n.data, "peer") })
	n.spawn(n.tickLoop)

	// Announce immediately instead of waiting out the first tick, so two nodes
	// started together see each other at once.
	n.beacon()
}

func (n *Node) spawn(fn func()) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		fn()
	}()
}

// Close stops the node. Closing the sockets is what unblocks the readers: a
// blocked ReadFromUDP returns net.ErrClosed immediately, which is simpler and
// more responsive than polling with read deadlines.
func (n *Node) Close() {
	n.closeOnce.Do(func() {
		close(n.done)
		n.data.Close()
		n.mcastIn.Close()
		n.mcastOut.Close()
	})
}

// Wait blocks until every goroutine has stopped, then closes the event channel
// so the CLI's printer can drain and exit. Closing it here, after all producers
// are known to be finished, is what makes sending on it safe elsewhere.
func (n *Node) Wait() {
	n.wg.Wait()
	n.waitOnce.Do(func() { close(n.events) })
}

// Events is the single stream of lines to show the user.
func (n *Node) Events() <-chan string { return n.events }

// Say queues lines from the CLI itself (command output, errors) onto the same
// stream as network events.
//
// Everything the user sees goes through one channel and is printed by one
// goroutine. The alternative — the CLI printing command output directly while a
// separate goroutine prints incoming messages — means two goroutines writing to
// stdout, which interleaves lines and scrambles their order. It must only be
// called before Wait, which is the point at which the channel is closed.
func (n *Node) Say(lines ...string) {
	for _, line := range lines {
		n.emit(line)
	}
}

// Sayf is Say with formatting.
func (n *Node) Sayf(format string, args ...any) { n.emit(fmt.Sprintf(format, args...)) }

// ---------------------------------------------------------------------------
// The loops
// ---------------------------------------------------------------------------

// readLoop is the same code for both sockets: read a datagram, hand it to the
// dispatcher, repeat. via records which socket it came from, because a HELLO
// arriving by unicast means something slightly different from one that arrived
// by multicast (see handleHello).
func (n *Node) readLoop(conn *net.UDPConn, via string) {
	buf := make([]byte, readBufferSize)
	for {
		count, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			// A closed socket is how shutdown reaches us, so it is not worth
			// reporting. Anything else during normal operation is.
			if errors.Is(err, net.ErrClosed) || n.stopping() {
				return
			}
			n.debugf("%s read error: %v", via, err)
			continue
		}

		n.received.Add(1)

		// Copy before parsing. buf is reused by the next iteration, and a CHAT
		// gets stored and later relayed verbatim, so it must own its bytes.
		frame := make([]byte, count)
		copy(frame, buf[:count])
		n.dispatch(frame, src, via)
	}
}

// writeLoop is the only code in the program that sends a packet.
func (n *Node) writeLoop() {
	for {
		select {
		case <-n.done:
			return
		case ob := <-n.sendq:
			var err error
			if ob.addr == nil {
				// The multicast sender is a connected socket, so a plain Write
				// goes to the group.
				_, err = n.mcastOut.Write(ob.frame)
			} else {
				_, err = n.data.WriteToUDP(ob.frame, ob.addr)
			}
			if err != nil {
				if errors.Is(err, net.ErrClosed) || n.stopping() {
					return
				}
				n.debugf("send %s failed: %v", ob.what, err)
				continue
			}
			n.logPacket(ob.routine, "-> %-12s %s (%d bytes)", ob.what, destination(ob.addr), len(ob.frame))
		}
	}
}

// tickLoop drives everything periodic. Three tickers share one goroutine
// because none of them do real work — they only queue packets — so there is no
// reason to pay for three goroutines and no risk of one blocking another.
func (n *Node) tickLoop() {
	beacon := time.NewTicker(beaconInterval)
	repair := time.NewTicker(antiEntropyInterval)
	sweep := time.NewTicker(sweepInterval)
	defer beacon.Stop()
	defer repair.Stop()
	defer sweep.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-beacon.C:
			n.beacon()
		case <-repair.C:
			n.antiEntropy()
		case <-sweep.C:
			n.expirePeers()
			n.maybeWarnIsolated()
		}
	}
}

// maybeWarnIsolated tells the user, once, that not a single packet has arrived.
//
// This is the failure everyone hits first, and without a message it is
// invisible: beacons leave successfully, so the program looks healthy while
// silently talking to nobody. The usual causes are a host firewall dropping
// inbound multicast, a guest/public network with client isolation, or a laptop
// with several adapters where discovery joined the wrong one.
func (n *Node) maybeWarnIsolated() {
	if n.hinted || n.received.Load() > 0 || n.peers.Len() > 0 {
		return
	}
	if time.Since(n.started) < isolationHintAfter {
		return
	}
	n.hinted = true

	n.emitf("! no packets received in %s, so discovery may be blocked here.", isolationHintAfter)
	n.emitf("!   - a firewall may be dropping inbound UDP to udp/%d (multicast)", n.group.Port)
	n.emitf("!   - discovery joined %s; use --iface to pick another interface", n.iface.Name)
	n.emitf("!   - to bypass discovery: run one node with --port 9101, the other with --peer <host>:9101")
}

// ---------------------------------------------------------------------------
// Periodic work
// ---------------------------------------------------------------------------

// beacon announces this node: to the multicast group, to a seeded address if
// there is one, and directly to every peer we already know.
//
// The multicast part is the whole of "zero configuration discovery": no server,
// no bootstrap list, no DNS. It is the same mechanism mDNS uses — periodic
// announcements to a multicast group, with peers expiring if the announcements
// stop — just with a compact signed record instead of DNS wire format.
//
// The direct copies to known peers are what make presence survive a network that
// carries multicast in only one direction, or not at all. Without them a peer
// reached over unicast hears from us exactly once, when it is first discovered,
// and then expires after peerTTL even though we are still here and still
// receiving its beacons. Refreshing over the same path we were reached on costs
// one small packet per peer per interval and removes that whole failure mode.
func (n *Node) beacon() {
	frame, err := crypto.BuildHello(n.id, n.dataPort)
	if err != nil {
		n.debugf("build hello: %v", err)
		return
	}
	n.enqueue(outbound{frame: frame, what: "HELLO", routine: true})

	// A seeded peer gets a direct copy even before it is a known peer. On a
	// network with multicast blocked (some corporate Wi-Fi, some VPNs, most
	// guest networks) this is the fallback that still involves no server: we
	// tell one known address we exist, it learns our address from the packet,
	// and the mesh forms from there.
	if n.seed != nil {
		n.enqueue(outbound{frame: frame, addr: n.seed, what: "HELLO/seed", routine: true})
	}

	for _, peer := range n.peers.Snapshot() {
		if n.seed != nil && sameAddr(peer.Addr, n.seed) {
			continue // already sent above
		}
		n.enqueue(outbound{frame: frame, addr: peer.Addr, what: "HELLO/peer", routine: true})
	}
}

// antiEntropy tells every peer which messages we hold.
//
// Push alone is lossy: UDP drops a packet and that message is simply gone from
// one node forever. This is the repair half — peers compare our digest against
// their own store and ask for what they are missing, which is what makes the
// mesh converge no matter which packets were lost, and what lets a node that
// was switched off catch up when it comes back.
func (n *Node) antiEntropy() {
	ids := n.store.Digest(digestSize)
	if len(ids) == 0 {
		return
	}
	frame, err := encodeIDList(codec.TypeHave, ids)
	if err != nil {
		n.debugf("build have: %v", err)
		return
	}
	for _, peer := range n.peers.Snapshot() {
		n.enqueue(outbound{frame: frame, addr: peer.Addr, what: "HAVE", routine: true})
	}
}

// expirePeers drops peers whose beacons have stopped.
func (n *Node) expirePeers() {
	for _, peer := range n.peers.Expire(peerTTL) {
		n.emitf("* %s (%s) went offline", peer.Name, peer.FP)
	}
}

// ---------------------------------------------------------------------------
// Inbound packets
// ---------------------------------------------------------------------------

// dispatch validates the frame and routes the body to a handler. Note the shape
// of the error handling: a malformed packet is logged at most and then dropped.
// Anyone on the network can send us nonsense, so nonsense must be ordinary.
func (n *Node) dispatch(frame []byte, src *net.UDPAddr, via string) {
	kind, body, err := codec.DecodeFrame(frame)
	if err != nil {
		n.debugf("drop %d bytes from %s on %s: %v", len(frame), src, via, err)
		return
	}
	// HELLO and HAVE are the periodic clockwork; a new peer or a real message
	// announces itself in the normal output anyway, so keep them out of
	// --verbose and show them only under --trace.
	routine := kind == codec.TypeHello || kind == codec.TypeHave
	n.logPacket(routine, "<- %-12s %s (%d bytes)", kind, src, len(frame))

	switch kind {
	case codec.TypeHello:
		n.handleHello(body, src, via)
	case codec.TypeChat:
		n.handleChat(frame, body, src)
	case codec.TypeHave:
		n.handleHave(body, src)
	case codec.TypeWant:
		n.handleWant(body, src)
	default:
		n.debugf("drop unknown message type %d from %s", kind, src)
	}
}

// handleHello records a peer.
func (n *Node) handleHello(body []byte, src *net.UDPAddr, via string) {
	hello, err := crypto.ParseHello(body)
	if err != nil {
		n.debugf("bad hello from %s: %v", src, err)
		return
	}

	fp := identity.FingerprintOf(hello.SignPub)

	// We receive our own multicast beacons, because IP multicast loopback is on
	// by default. Without this check a node would list itself as a peer and
	// echo its own messages back to itself.
	if fp == n.id.Fingerprint() {
		return
	}

	// The peer's address is the source IP of the packet combined with the port
	// it advertised. We deliberately do not trust the source port: the beacon
	// leaves from the multicast socket, so its source port is not where replies
	// should go.
	peer := discovery.Peer{
		FP:   fp,
		Name: hello.Name,
		Addr: &net.UDPAddr{IP: src.IP, Port: int(hello.DataPort)},
	}
	copy(peer.BoxPub[:], hello.BoxPub)

	if isNew := n.peers.Upsert(peer); isNew {
		n.emitf("* %s (%s) is online at %s", peer.Name, peer.FP, peer.Addr)

		// If this introduction arrived by unicast, multicast may be blocked in
		// one direction, so answer directly rather than assuming our beacon
		// will reach them. This is what makes --peer work symmetrically.
		if via == "peer" {
			if frame, err := crypto.BuildHello(n.id, n.dataPort); err == nil {
				n.enqueue(outbound{frame: frame, addr: peer.Addr, what: "HELLO/reply"})
			}
		}
	}
}

// handleChat is the heart of the gossip protocol.
//
// The order of these steps is the security-relevant part: verify before
// storing, deduplicate before doing work, and relay whether or not we could
// read the contents.
func (n *Node) handleChat(frame, body []byte, src *net.UDPAddr) {
	chat, err := codec.UnmarshalChat(body)
	if err != nil {
		n.debugf("bad chat from %s: %v", src, err)
		return
	}
	if err := crypto.VerifyChat(chat); err != nil {
		// Either a forgery or a replay of something captured earlier. Either
		// way it never reaches the store, so it can neither be displayed nor
		// relayed onward by us.
		n.debugf("reject chat from %s: %v", src, err)
		return
	}
	if n.store.Has(chat.ID) {
		// Already seen. Stopping here is what keeps a flood from circulating
		// forever in a mesh where everyone forwards to everyone.
		return
	}

	senderFP := identity.FingerprintOf(chat.SenderSignPub)
	entry := &gossip.Entry{
		ID:       chat.ID,
		Raw:      frame,
		SenderFP: senderFP,
		Sender:   n.displayName(senderFP),
		TS:       chat.TS,
	}
	// Decryption succeeds only if the sender wrapped the message key for us.
	// A node that cannot read a message still stores and forwards it, which
	// turns partly-connected and late-joining nodes into useful carriers
	// instead of dead ends — and means a relay learns nothing from the traffic
	// it carries.
	if text, ok := crypto.OpenChat(chat, n.id); ok {
		entry.Text = text
		entry.Readable = true
	}
	if !n.store.Add(entry) {
		return
	}

	if entry.Readable {
		n.emit(formatMessage(entry))
	} else {
		n.debugf("relaying a message not addressed to us (%x)", entry.ID[:4])
	}

	// Forward the original bytes, not a re-encoding: the signature covers the
	// exact byte sequence, and passing the original along means a relay cannot
	// alter anything even by accident.
	n.fanout(frame, src, "CHAT/relay")
}

// handleHave answers "here is what I hold" with "then send me these".
func (n *Node) handleHave(body []byte, src *net.UDPAddr) {
	list, err := codec.UnmarshalIDList(body)
	if err != nil {
		n.debugf("bad have from %s: %v", src, err)
		return
	}
	missing := n.store.Missing(list.IDs)
	if len(missing) == 0 {
		return
	}
	frame, err := encodeIDList(codec.TypeWant, missing)
	if err != nil {
		n.debugf("build want: %v", err)
		return
	}
	n.enqueue(outbound{frame: frame, addr: src, what: "WANT"})
}

// handleWant resends stored messages that a peer is missing.
//
// Any node that holds a message answers, not just its author. That is what
// makes history survive people leaving, and it is the difference between a
// peer-to-peer mesh and a network of one-to-many broadcasters.
//
// HAVE and WANT are deliberately unauthenticated, because they carry no secrets
// and their contents are already public knowledge to anyone sniffing the LAN.
// The one abuse they enable is amplification: a forged WANT asking for many
// messages. wantReplyCap bounds that, and the replies only ever go to the
// address that asked, which already sees this traffic.
func (n *Node) handleWant(body []byte, src *net.UDPAddr) {
	list, err := codec.UnmarshalIDList(body)
	if err != nil {
		n.debugf("bad want from %s: %v", src, err)
		return
	}
	sent := 0
	for _, id := range list.IDs {
		if sent >= wantReplyCap {
			return
		}
		if raw, ok := n.store.Raw(id); ok {
			n.enqueue(outbound{frame: raw, addr: src, what: "CHAT/repair"})
			sent++
		}
	}
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

// Compose encrypts, signs, stores and sends a message the user typed.
func (n *Node) Compose(text string) error {
	peers := n.peers.Snapshot()

	// Recipients are the peers we currently know about, plus ourselves so that
	// our own history stays readable. Everyone must be wrapped in at send time:
	// there is no way to add a recipient to a message after the fact, which is
	// why a peer who joins later cannot read older messages.
	recipients := make([]crypto.Recipient, 0, len(peers)+1)
	recipients = append(recipients, crypto.Recipient{FP: n.id.Fingerprint(), BoxPub: n.id.BoxPub})
	truncated := 0
	for _, peer := range peers {
		if len(recipients) >= crypto.MaxRecipients {
			truncated++
			continue
		}
		recipients = append(recipients, crypto.Recipient{FP: peer.FP, BoxPub: peer.BoxPub})
	}

	chat, frame, err := crypto.BuildChat(n.id, text, recipients)
	if err != nil {
		return err
	}

	entry := &gossip.Entry{
		ID:       chat.ID,
		Raw:      frame,
		SenderFP: n.id.Fingerprint(),
		Sender:   n.id.Name,
		TS:       chat.TS,
		Text:     text,
		Readable: true,
	}
	n.store.Add(entry)
	n.emit(formatMessage(entry))

	if len(peers) == 0 {
		n.emit("! nobody is online yet, so that message stayed on this node")
		return nil
	}
	if truncated > 0 {
		n.emitf("! %d peer(s) left out: a single datagram fits at most %d recipients", truncated, crypto.MaxRecipients)
	}
	n.fanout(frame, nil, "CHAT")
	return nil
}

// fanout queues a frame for every known peer, optionally skipping the address it
// arrived from (there is no point sending a message back to whoever just sent
// it to us).
func (n *Node) fanout(frame []byte, except *net.UDPAddr, what string) {
	for _, peer := range n.peers.Snapshot() {
		if except != nil && sameAddr(peer.Addr, except) {
			continue
		}
		n.enqueue(outbound{frame: frame, addr: peer.Addr, what: what})
	}
}

// enqueue hands a datagram to the writer, never blocking.
//
// Dropping a packet when the queue is full is the correct behaviour for this
// program: UDP is already unreliable, anti-entropy repairs losses, and blocking
// here would stall a read loop and let a flood turn into unbounded memory use.
func (n *Node) enqueue(ob outbound) {
	select {
	case n.sendq <- ob:
	default:
		n.debugf("send queue full, dropped %s", ob.what)
	}
}

// ---------------------------------------------------------------------------
// Views for the CLI
// ---------------------------------------------------------------------------

// Banner describes this node at startup.
func (n *Node) Banner() []string {
	keyNote := "loaded"
	if n.freshKey {
		keyNote = "created"
	}
	lines := []string{
		fmt.Sprintf("gossipmesh: %s  fingerprint %s", n.id.Name, n.id.Fingerprint()),
		fmt.Sprintf("       identity %s (%s)", identity.KeyPath(n.cfg.DataDir, n.id.Name), keyNote),
		fmt.Sprintf("       discovery %s on %s (%s)", n.group, n.iface.Name, n.localIP),
		fmt.Sprintf("       peer traffic on udp/%d", n.dataPort),
	}
	if n.seed != nil {
		lines = append(lines, fmt.Sprintf("       seeding directly to %s", n.seed))
	}
	return lines
}

// Whoami answers "which key am I using", the value a user reads out to a
// contact to confirm they are talking to the right person.
func (n *Node) Whoami() string {
	return fmt.Sprintf("you are %s (%s) on udp/%d", n.id.Name, n.id.Fingerprint(), n.dataPort)
}

// PeerLines renders the peer table.
func (n *Node) PeerLines() []string {
	peers := n.peers.Snapshot()
	if len(peers) == 0 {
		return []string{"no peers yet (are both nodes on the same network?)"}
	}
	lines := make([]string, 0, len(peers)+1)
	lines = append(lines, fmt.Sprintf("%d peer(s):", len(peers)))
	for _, peer := range peers {
		lines = append(lines, fmt.Sprintf("  %-16s %s  %s  last seen %.0fs ago",
			peer.Name, peer.FP, peer.Addr, time.Since(peer.LastSeen).Seconds()))
	}
	return lines
}

// HistoryLines renders what this node is holding, including messages it is only
// carrying for others.
func (n *Node) HistoryLines() []string {
	entries := n.store.Recent(20)
	if len(entries) == 0 {
		return []string{"no messages yet"}
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, formatMessage(entry))
	}
	return lines
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func formatMessage(e *gossip.Entry) string {
	stamp := time.UnixMilli(e.TS).Format("15:04")
	if !e.Readable {
		// Shown by /history so it is obvious that a node stores and relays
		// ciphertext it cannot read.
		return fmt.Sprintf("[%s] %s(%s): <encrypted, not addressed to you>", stamp, e.Sender, e.SenderFP)
	}
	return fmt.Sprintf("[%s] %s(%s): %s", stamp, e.Sender, e.SenderFP, e.Text)
}

// displayName resolves a fingerprint to something readable. Names come from
// peers and are therefore untrusted: two peers may claim the same name, which is
// exactly why the fingerprint is always printed alongside it.
func (n *Node) displayName(fp identity.Fingerprint) string {
	if fp == n.id.Fingerprint() {
		return n.id.Name
	}
	if peer, ok := n.peers.Lookup(fp); ok {
		return peer.Name
	}
	return "unknown"
}

func (n *Node) stopping() bool {
	select {
	case <-n.done:
		return true
	default:
		return false
	}
}

// emit queues a line for the user, dropping it rather than blocking if the CLI
// has fallen behind. A network loop must never be stalled by a slow terminal.
func (n *Node) emit(line string) {
	select {
	case n.events <- line:
	default:
	}
}

func (n *Node) emitf(format string, args ...any) { n.emit(fmt.Sprintf(format, args...)) }

// debugf reports something that actually happened: a message moving, a packet
// rejected, a send failing. Shown under --verbose.
func (n *Node) debugf(format string, args ...any) {
	if n.cfg.Verbose || n.cfg.Trace {
		n.logLine(format, args...)
	}
}

// tracef reports clockwork traffic. Shown only under --trace.
func (n *Node) tracef(format string, args ...any) {
	if n.cfg.Trace {
		n.logLine(format, args...)
	}
}

func (n *Node) logPacket(routine bool, format string, args ...any) {
	if routine {
		n.tracef(format, args...)
		return
	}
	n.debugf(format, args...)
}

// logLine timestamps to milliseconds, because the interesting thing about a
// gossip trace is the timing: when a beacon goes out, how quickly a relay
// follows a receive.
func (n *Node) logLine(format string, args ...any) {
	n.emit("  · " + time.Now().Format("15:04:05.000") + " " + fmt.Sprintf(format, args...))
}

func encodeIDList(kind codec.MsgType, ids [][codec.IDSize]byte) ([]byte, error) {
	body, err := (&codec.IDList{IDs: ids}).Marshal()
	if err != nil {
		return nil, err
	}
	return codec.EncodeFrame(kind, body)
}

func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

func destination(addr *net.UDPAddr) string {
	if addr == nil {
		return "multicast"
	}
	return addr.String()
}
