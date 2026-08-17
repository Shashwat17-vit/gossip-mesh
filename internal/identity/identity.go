// Package identity owns the only state a node keeps on disk: its keys.
//
// A node carries TWO keypairs, and understanding why is the single most
// important thing in this package:
//
//	Ed25519  -> signing.    Proves "this peer produced these exact bytes".
//	X25519   -> encryption. Lets other peers encrypt a secret to us (NaCl box).
//
// Both public keys are 32 bytes, which makes them look interchangeable. They
// are not. Ed25519 keys live on the Edwards form of Curve25519 (a compressed
// y-coordinate), while NaCl's box uses the Montgomery form (a u-coordinate).
// Handing one to a function expecting the other produces garbage rather than an
// error, which is the worst kind of bug. A conversion is mathematically
// possible but fiddly, and reusing a single key for both signing and key
// agreement is discouraged anyway, so we simply generate both.
//
// The private keys never leave this package. Instead of exposing them, we
// expose the two operations that need them (Sign and Unseal), so no other
// package can accidentally log, copy, or serialize secret material.
package identity

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// SeedSize is the number of secret bytes an Ed25519 identity needs. Go's
	// ed25519.PrivateKey is 64 bytes, but that is only a convenience: it stores
	// seed||publicKey. The seed alone reconstructs everything, so the keyfile
	// stores 32 bytes and derives the rest.
	SeedSize = 32

	// FingerprintSize is how many bytes of the public key hash we show users.
	// 8 bytes (16 hex characters) is short enough to read aloud over a phone
	// call and long enough to make collisions on a LAN a non-issue.
	FingerprintSize = 8

	keyFileMagic = "gossipmesh-key-v1"
)

// Fingerprint is the short, human-checkable name of a peer, derived from its
// signing public key. Because it is a hash of a key rather than an assigned
// label, identity is self-certifying: no registry or server has to vouch for
// it, and any peer can verify the mapping themselves. This is the same idea as
// libp2p's PeerId, or an SSH host key fingerprint.
type Fingerprint [FingerprintSize]byte

// String renders the fingerprint as hex, which is what the CLI prints and what
// two users compare out of band to be sure they are talking to each other.
func (f Fingerprint) String() string { return hex.EncodeToString(f[:]) }

// FingerprintOf derives a fingerprint from any signing public key, so we can
// name a peer straight from a packet before we know anything else about them.
func FingerprintOf(signPub []byte) Fingerprint {
	sum := sha256.Sum256(signPub)
	var fp Fingerprint
	copy(fp[:], sum[:FingerprintSize])
	return fp
}

// Identity is one node's cryptographic self. The public halves are exported
// because they are broadcast to the world in every HELLO; the private halves
// are not.
type Identity struct {
	Name    string
	SignPub ed25519.PublicKey
	BoxPub  [32]byte

	signPriv ed25519.PrivateKey
	signSeed [SeedSize]byte
	boxPriv  [32]byte
}

// Generate creates a brand new identity from the operating system's CSPRNG.
func Generate(name string) (*Identity, error) {
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("identity: read seed: %w", err)
	}
	_, boxPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate box key: %w", err)
	}
	return derive(name, seed, *boxPriv)
}

// derive rebuilds the full identity from just the two secrets. Both the
// generate path and the load-from-disk path go through here, which guarantees a
// restored identity is bit-identical to the original.
func derive(name string, seed [SeedSize]byte, boxPriv [32]byte) (*Identity, error) {
	signPriv := ed25519.NewKeyFromSeed(seed[:])

	// The X25519 public key is the private scalar multiplied by the curve's
	// base point, so it never needs storing: it is always recomputable.
	boxPubBytes, err := curve25519.X25519(boxPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("identity: derive box public key: %w", err)
	}

	id := &Identity{
		Name:     name,
		SignPub:  signPriv.Public().(ed25519.PublicKey),
		signPriv: signPriv,
		signSeed: seed,
		boxPriv:  boxPriv,
	}
	copy(id.BoxPub[:], boxPubBytes)
	return id, nil
}

// Fingerprint returns this node's own short name.
func (i *Identity) Fingerprint() Fingerprint { return FingerprintOf(i.SignPub) }

// Sign produces a 64-byte Ed25519 signature over msg.
//
// Ed25519 signing is deterministic: the per-signature nonce is derived by
// hashing the private seed together with the message, so no random number
// generator is involved at signing time. That removes the failure mode that
// leaked Sony's PS3 signing key, where a repeated ECDSA nonce exposed the
// private key outright.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.signPriv, msg) }

// Verify checks a signature against a peer's advertised signing key. It is a
// package-level function rather than a method because verification only ever
// involves someone else's public key.
func Verify(signPub []byte, msg, sig []byte) bool {
	if len(signPub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(signPub), msg, sig)
}

// Seal encrypts a small secret (in this project, a 32-byte message key) to a
// recipient's X25519 public key using a NaCl "sealed box".
//
// Why the anonymous variant instead of box.Seal: a sealed box generates a
// throwaway keypair per message and derives the nonce from it, so the sender
// needs no key of their own and there is no nonce to manage — deleting an
// entire category of nonce-reuse bug. We do not lose sender authenticity,
// because every message is separately signed with Ed25519.
func Seal(recipientBoxPub *[32]byte, msg []byte) ([]byte, error) {
	sealed, err := box.SealAnonymous(nil, msg, recipientBoxPub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: seal: %w", err)
	}
	return sealed, nil
}

// Unseal reverses Seal using our private key. ok is false whenever the box was
// not meant for us or has been tampered with — sealed boxes are authenticated,
// so a corrupted ciphertext fails rather than decrypting to noise.
func (i *Identity) Unseal(sealed []byte) (msg []byte, ok bool) {
	return box.OpenAnonymous(nil, sealed, &i.BoxPub, &i.boxPriv)
}

// SealedSize is the on-wire length of Seal's output for a plaintext of n bytes.
// box.AnonymousOverhead is 48: a 16-byte Poly1305 tag plus the 32-byte
// ephemeral public key that the recipient needs in order to open the box.
func SealedSize(n int) int { return n + box.AnonymousOverhead }

// Load returns the identity stored for name under dir, creating and saving a
// new one on first run. created reports which happened, so the CLI can tell the
// user a new fingerprint was minted.
//
// Persistence matters more than it looks: if a node generated fresh keys on
// every start, it would appear to its peers as a brand-new stranger each time,
// and comparing fingerprints out of band would be pointless.
func Load(dir, name string) (id *Identity, created bool, err error) {
	path := KeyPath(dir, name)

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		id, err = parseKeyFile(name, data)
		if err != nil {
			return nil, false, fmt.Errorf("identity: %s: %w", path, err)
		}
		return id, false, nil

	case errors.Is(err, os.ErrNotExist):
		id, err = Generate(name)
		if err != nil {
			return nil, false, err
		}
		if err := id.Save(dir); err != nil {
			return nil, false, err
		}
		return id, true, nil

	default:
		return nil, false, fmt.Errorf("identity: read %s: %w", path, err)
	}
}

// KeyPath is where a given identity lives on disk.
func KeyPath(dir, name string) string { return filepath.Join(dir, name+".key") }

// Save writes the two secrets as a small line-based text file.
//
// A readable format is a deliberate choice for a learning project: you can open
// the file and see exactly what a node's identity consists of. Mode 0600 asks
// the OS to keep it owner-only, though on Windows that is advisory rather than
// enforced.
func (i *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: create %s: %w", dir, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", keyFileMagic)
	fmt.Fprintf(&b, "name %s\n", i.Name)
	fmt.Fprintf(&b, "sign-seed %s\n", hex.EncodeToString(i.signSeed[:]))
	fmt.Fprintf(&b, "box-priv %s\n", hex.EncodeToString(i.boxPriv[:]))

	path := KeyPath(dir, i.Name)
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

func parseKeyFile(name string, data []byte) (*Identity, error) {
	var (
		seed    [SeedSize]byte
		boxPriv [32]byte
		sawSeed bool
		sawBox  bool
	)

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != keyFileMagic {
		return nil, fmt.Errorf("not a %s file", keyFileMagic)
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("malformed line %q", line)
		}
		switch key {
		case "name":
			// The filename is authoritative; the stored name is informational.
		case "sign-seed":
			if err := decodeHexInto(seed[:], value); err != nil {
				return nil, fmt.Errorf("sign-seed: %w", err)
			}
			sawSeed = true
		case "box-priv":
			if err := decodeHexInto(boxPriv[:], value); err != nil {
				return nil, fmt.Errorf("box-priv: %w", err)
			}
			sawBox = true
		default:
			return nil, fmt.Errorf("unknown field %q", key)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !sawSeed || !sawBox {
		return nil, errors.New("keyfile is missing sign-seed or box-priv")
	}
	return derive(name, seed, boxPriv)
}

func decodeHexInto(dst []byte, s string) error {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(raw) != len(dst) {
		return fmt.Errorf("expected %d bytes, got %d", len(dst), len(raw))
	}
	copy(dst, raw)
	return nil
}
