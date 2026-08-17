// Package crypto turns a line of text into a message that is safe to shout
// across a hostile network, and back again.
//
// The threat model it is built for: anyone in the same cafe can passively sniff
// every packet and can also inject packets of their own. So every message is
//
//	signed     with Ed25519, so an injected or altered message is rejected
//	encrypted  so a sniffer sees only ciphertext
//
// The interesting decision is the ENCRYPTION SHAPE. Encrypting the whole message
// separately for each of N peers would multiply its size by N and blow past the
// one-datagram budget on a single paragraph. So this is hybrid ("lockbox")
// encryption instead:
//
//  1. invent a fresh random 32-byte message key
//  2. encrypt the text once with it (secretbox) — 16 bytes of overhead, once
//  3. wrap that key separately for each recipient (sealed box) — 80 bytes each
//
// The body is paid for once and each extra recipient costs only 80 bytes. This
// is the same construction as encrypted email to multiple people, and it is why
// a peer who joins later cannot read older history: nobody wrapped the key for
// them at the time, and there is no way to retrofit it.
//
// What this deliberately does NOT provide is forward secrecy. Long-term keys
// wrap every message key, so a stolen key file decrypts any traffic captured
// earlier. Real forward secrecy needs an ephemeral handshake per session (Noise)
// or a ratchet (Signal, MLS), which is a much larger project.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"gossipmesh/internal/codec"
	"gossipmesh/internal/identity"
)

const (
	// MaxRecipients bounds how many peers one message can be addressed to, so a
	// full-house message still fits in one datagram. The arithmetic: 10 bytes of
	// frame, ~147 bytes of fixed CHAT fields, 88 bytes per recipient
	// (fingerprint hint + wrapped key), plus the ciphertext.
	MaxRecipients = 8

	// MaxTextBytes is what is left for the text itself once the above is paid
	// for. Rejecting a long message with a clear error is better than emitting a
	// datagram that fragments and then mysteriously fails to arrive.
	MaxTextBytes = 300

	// ClockSkew is how far a message's timestamp may be from our clock.
	//
	// This is replay protection. Without it, an attacker could re-send a
	// perfectly valid message captured hours ago — the signature would still
	// verify, because it always will. It also bounds how long the seen-set has
	// to remember an id in order to be effective.
	ClockSkew = 5 * time.Minute

	messageKeySize = 32
)

var (
	ErrEmptyText    = errors.New("crypto: message is empty")
	ErrTextTooLong  = errors.New("crypto: message too long")
	ErrNoRecipients = errors.New("crypto: no recipients")
	ErrTooManyRcpts = errors.New("crypto: too many recipients")
	ErrBadSignature = errors.New("crypto: signature does not verify")
	ErrStale        = errors.New("crypto: timestamp outside the accepted window")
	ErrMalformed    = errors.New("crypto: malformed message")
)

// Recipient is a peer we can encrypt to: their fingerprint (a lookup hint on the
// wire) and their X25519 public key (what actually does the encrypting).
type Recipient struct {
	FP     identity.Fingerprint
	BoxPub [32]byte
}

// ---------------------------------------------------------------------------
// HELLO
// ---------------------------------------------------------------------------

// BuildHello produces a signed, framed presence beacon ready to send.
//
// The signature is what makes discovery trustworthy. A HELLO carries the peer's
// encryption key, so if it were unsigned an attacker could announce their own
// BoxPub under the name "alice" and everyone would happily encrypt to them. The
// signature binds the encryption key to the signing key, and the fingerprint
// users compare out of band is derived from the signing key.
func BuildHello(id *identity.Identity, dataPort uint16) ([]byte, error) {
	hello := &codec.Hello{
		Name:     id.Name,
		SignPub:  id.SignPub,
		BoxPub:   id.BoxPub[:],
		DataPort: dataPort,
		TS:       time.Now().UnixMilli(),
	}

	signing, err := hello.SigningBytes()
	if err != nil {
		return nil, err
	}
	hello.Sig = id.Sign(signing)

	body, err := hello.Marshal()
	if err != nil {
		return nil, err
	}
	return codec.EncodeFrame(codec.TypeHello, body)
}

// ParseHello decodes and fully validates an inbound beacon. A caller that gets a
// Hello back may trust its contents; anything suspect is an error instead.
func ParseHello(body []byte) (*codec.Hello, error) {
	hello, err := codec.UnmarshalHello(body)
	if err != nil {
		return nil, err
	}

	signing, err := hello.SigningBytes()
	if err != nil {
		return nil, err
	}
	if !identity.Verify(hello.SignPub, signing, hello.Sig) {
		return nil, ErrBadSignature
	}
	if err := checkFresh(hello.TS); err != nil {
		return nil, err
	}
	if hello.DataPort == 0 {
		return nil, fmt.Errorf("%w: hello advertises port 0", ErrMalformed)
	}
	return hello, nil
}

// ---------------------------------------------------------------------------
// CHAT
// ---------------------------------------------------------------------------

// BuildChat encrypts and signs one message, returning both the parsed form (for
// local storage) and the framed bytes (for the wire).
func BuildChat(id *identity.Identity, text string, recipients []Recipient) (*codec.Chat, []byte, error) {
	// Sanitize our own outgoing text too, not just inbound text: a pasted
	// terminal escape sequence should not be something one user can send to
	// another's screen.
	text = codec.SanitizeLine(text)
	switch {
	case text == "":
		return nil, nil, ErrEmptyText
	case len(text) > MaxTextBytes:
		return nil, nil, fmt.Errorf("%w: %d bytes, limit %d", ErrTextTooLong, len(text), MaxTextBytes)
	case len(recipients) == 0:
		return nil, nil, ErrNoRecipients
	case len(recipients) > MaxRecipients:
		return nil, nil, fmt.Errorf("%w: %d, limit %d", ErrTooManyRcpts, len(recipients), MaxRecipients)
	}

	chat := &codec.Chat{
		TS:            time.Now().UnixMilli(),
		SenderSignPub: id.SignPub,
	}

	// A random id, rather than a counter or a content hash. A counter would need
	// coordination between nodes, and a hash would make two identical messages
	// indistinguishable — which would silently swallow the second one, since the
	// mesh deduplicates by id.
	if _, err := rand.Read(chat.ID[:]); err != nil {
		return nil, nil, fmt.Errorf("crypto: read message id: %w", err)
	}
	if _, err := rand.Read(chat.Nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("crypto: read nonce: %w", err)
	}

	// A fresh key per message. Because it is never reused, the nonce could even
	// have been a constant; we randomize it anyway so that no property of the
	// scheme depends on that argument staying true.
	var messageKey [messageKeySize]byte
	if _, err := rand.Read(messageKey[:]); err != nil {
		return nil, nil, fmt.Errorf("crypto: read message key: %w", err)
	}

	chat.Ciphertext = secretbox.Seal(nil, []byte(text), &chat.Nonce, &messageKey)

	for _, rcpt := range recipients {
		boxPub := rcpt.BoxPub
		wrapped, err := identity.Seal(&boxPub, messageKey[:])
		if err != nil {
			return nil, nil, err
		}
		entry := codec.Recipient{WrappedKey: wrapped}
		copy(entry.FP[:], rcpt.FP[:])
		chat.Recipients = append(chat.Recipients, entry)
	}

	signing, err := chat.SigningBytes()
	if err != nil {
		return nil, nil, err
	}
	chat.Sig = id.Sign(signing)

	body, err := chat.Marshal()
	if err != nil {
		return nil, nil, err
	}
	frame, err := codec.EncodeFrame(codec.TypeChat, body)
	if err != nil {
		return nil, nil, err
	}
	return chat, frame, nil
}

// VerifyChat authenticates a message. It must be called before a message is
// stored, displayed, or relayed — a node that forwarded unverified messages
// would be doing an attacker's distribution work for them.
func VerifyChat(chat *codec.Chat) error {
	signing, err := chat.SigningBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(chat.SenderSignPub, signing, chat.Sig) {
		return ErrBadSignature
	}
	return checkFresh(chat.TS)
}

// OpenChat decrypts a message if it was addressed to us.
//
// ok is false for the perfectly ordinary case of a message meant for someone
// else, which the caller treats as "store and relay, but do not display".
func OpenChat(chat *codec.Chat, id *identity.Identity) (text string, ok bool) {
	mine := id.Fingerprint()

	for _, rcpt := range chat.Recipients {
		// The fingerprint is only a hint that saves us trying to open every
		// wrapped key. Being wrong is harmless: the sealed box below is
		// authenticated, so it simply fails to open.
		if string(rcpt.FP[:]) != string(mine[:]) {
			continue
		}
		keyBytes, opened := id.Unseal(rcpt.WrappedKey)
		if !opened || len(keyBytes) != messageKeySize {
			continue
		}

		var messageKey [messageKeySize]byte
		copy(messageKey[:], keyBytes)

		plaintext, opened := secretbox.Open(nil, chat.Ciphertext, &chat.Nonce, &messageKey)
		if !opened {
			continue
		}
		return codec.SanitizeLine(string(plaintext)), true
	}
	return "", false
}

// checkFresh rejects timestamps too far from our clock in either direction.
// Future timestamps are allowed within the same window because peers' clocks
// genuinely differ; the point is to bound the window, not to trust the sender.
func checkFresh(ts int64) error {
	age := time.Since(time.UnixMilli(ts))
	if age < 0 {
		age = -age
	}
	if age > ClockSkew {
		return fmt.Errorf("%w: %s off", ErrStale, age.Round(time.Second))
	}
	return nil
}
