// Command gossipmesh is a serverless, encrypted chat client for a local network.
//
// Run it in two terminals on the same Wi-Fi or LAN and the two nodes find each
// other with no configuration, no server, and no DNS:
//
//	gossipmesh --name alice
//	gossipmesh --name bob
//
// Read this file first. It is the whole program from the outside — everything
// below it in internal/ exists to serve these ~200 lines. The layering is:
//
//	cmd/gossipmesh   this file: flags, terminal in, terminal out
//	internal/node    the orchestrator: sockets, goroutines, packet handling
//	internal/crypto  sign, verify, encrypt, decrypt one message
//	internal/gossip  which messages we hold, and what we are missing
//	internal/discovery who else is on the network right now
//	internal/transport UDP sockets, unicast and multicast
//	internal/codec   structs <-> bytes on the wire
//	internal/identity our keys, and what a peer's name means
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gossipmesh/internal/node"
)

func main() {
	// A single flag set, no CLI framework. There is one command and a handful
	// of flags, so a dependency to print help text would not earn its keep, and
	// a reader can see the entire interface of the program in one screen.
	cfg := node.Config{}
	flag.StringVar(&cfg.Name, "name", "", "nickname other peers see (letters, digits, - and _; required)")
	flag.StringVar(&cfg.DataDir, "data-dir", ".gossipmesh", "directory holding this node's key file")
	flag.IntVar(&cfg.DataPort, "port", 0, "UDP port for peer traffic (0 = pick a free one; pin it only if peers must reach you with --peer)")
	flag.StringVar(&cfg.Iface, "iface", "", "network interface to use for discovery (default: first usable one)")
	flag.StringVar(&cfg.Group, "group", node.DefaultGroup, "IPv4 multicast group used for discovery")
	flag.IntVar(&cfg.DiscoveryPort, "discovery-port", node.DefaultDiscoveryPort, "UDP port every node listens on for HELLO beacons")
	flag.StringVar(&cfg.Seed, "peer", "", "optional host:port of a known peer, for networks where multicast is blocked")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "log real events: messages sent, relayed and rejected")
	flag.BoolVar(&cfg.Trace, "trace", false, "also log every beacon and digest (very chatty)")
	flag.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "gossipmesh: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg node.Config) error {
	if err := validateName(cfg.Name); err != nil {
		return err
	}

	// One context governs the lifetime of everything. Ctrl+C cancels it, which
	// unwinds every goroutine the node started; there is no other shutdown path
	// to get wrong.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	n, err := node.New(cfg)
	if err != nil {
		return err
	}

	for _, line := range n.Banner() {
		fmt.Println(line)
	}
	fmt.Println("type a message and press enter. /help lists commands.")
	fmt.Println()

	n.Start(ctx)

	// Everything the node wants to show the user arrives on one channel, and
	// exactly one goroutine writes to stdout. If the network loops printed
	// directly they would interleave mid-line with each other and with this
	// terminal's echo.
	printing := make(chan struct{})
	go func() {
		defer close(printing)
		for line := range n.Events() {
			fmt.Println(line)
		}
	}()

	readCommands(ctx, n)

	stop()    // stop trapping signals, so a second Ctrl+C kills us outright
	n.Close() // close sockets, which unblocks the reader goroutines
	n.Wait()  // let them finish so nothing logs after we have said goodbye
	<-printing

	fmt.Println("gossipmesh: offline")
	return nil
}

// readCommands turns terminal input into node actions, and returns when the
// user leaves or the context is cancelled.
func readCommands(ctx context.Context, n *node.Node) {
	// Reading stdin has to happen on its own goroutine: scanner.Scan blocks
	// until the user presses enter, and there is no portable way to interrupt
	// it. Keeping it separate means Ctrl+C is still responsive while we wait,
	// and this goroutine simply dies with the process.
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		close(lines) // EOF: the user piped input, or pressed Ctrl+D/Ctrl+Z
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-lines:
			if !ok {
				return
			}
			if quit := handleLine(n, strings.TrimSpace(line)); quit {
				return
			}
		}
	}
}

// handleLine dispatches one line of input. Anything that is not a slash command
// is a message to send.
//
// Output goes through n.Say rather than fmt.Println so that command results,
// error messages and incoming chat all pass through the same queue and appear in
// the order they actually happened.
func handleLine(n *node.Node, line string) (quit bool) {
	if line == "" {
		return false
	}
	if !strings.HasPrefix(line, "/") {
		if err := n.Compose(line); err != nil {
			n.Sayf("! %v", err)
		}
		return false
	}

	switch cmd, _, _ := strings.Cut(line, " "); cmd {
	case "/quit", "/exit":
		return true

	case "/peers":
		n.Say(n.PeerLines()...)

	case "/whoami":
		n.Say(n.Whoami())

	case "/history":
		n.Say(n.HistoryLines()...)

	case "/help":
		n.Say(
			"  /peers    who is online right now",
			"  /whoami   your name and fingerprint",
			"  /history  messages this node is holding",
			"  /quit     leave",
		)

	default:
		n.Sayf("! unknown command %q, try /help", cmd)
	}
	return false
}

// validateName keeps nicknames boring on purpose. The name is used as a
// filename for the key file and is printed to other people's terminals, so
// restricting it to a safe alphabet here means neither of those has to worry
// about path separators or escape sequences later.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("--name is required (try --name %s)", "alice")
	}
	if len(name) > 24 {
		return fmt.Errorf("--name must be at most 24 characters")
	}
	for _, r := range name {
		ok := r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("--name may only contain letters, digits, - and _ (got %q)", r)
		}
	}
	return nil
}
