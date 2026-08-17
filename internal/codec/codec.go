// Package codec turns Go structs into the exact bytes that travel in a UDP
// datagram, and back again.
//
// This is hand-written rather than JSON for two reasons, one practical and one
// that is a genuine correctness requirement:
//
//  1. Size. Every message must fit in a single datagram (see MaxDatagram), and
//     JSON would roughly double the overhead of what is mostly binary key
//     material anyway.
//
//  2. Determinism. A signature covers an exact byte sequence. JSON has no
//     canonical form — map ordering, whitespace and number formatting can all
//     vary — so re-serializing a decoded message could produce different bytes
//     and break verification. A fixed binary layout is deterministic by
//     construction.
//
// This package is also the security boundary of the program: it is the first
// code to touch bytes that an attacker on the same Wi-Fi network chose. So the
// rules here are strict. Every length is validated against the data actually
// present, decoding never trusts a length prefix, trailing bytes are rejected
// rather than ignored, and decoded values are copied out of the read buffer so
// nothing aliases memory that the next packet will overwrite.
package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Wire limits.
const (
	// Magic marks our traffic. Go's multicast listener binds 0.0.0.0, so it
	// receives anything sent to our port by any program; this rejects that
	// cheaply before we try to interpret it.
	Magic = "GMSH"

	// Version lets the format change later without older nodes silently
	// misparsing newer packets.
	Version = 1

	// HeaderSize is magic(4) + version(1) + type(1) + bodyLength(4).
	HeaderSize = 10

	// MaxDatagram keeps a whole frame under the ~1500-byte Ethernet MTU with
	// room to spare. Staying under the MTU matters because a fragmented IP
	// datagram is lost entirely if any single fragment is dropped, which would
	// make large messages mysteriously unreliable rather than merely slower.
	MaxDatagram = 1400

	// MaxBodySize is what is left for a message body after the frame header.
	MaxBodySize = MaxDatagram - HeaderSize
)

// Fixed field sizes, all dictated by the crypto primitives we use.
const (
	IDSize         = 16 // random message id
	FPSize         = 8  // truncated fingerprint used as a recipient hint
	SignPubSize    = 32 // ed25519 public key
	BoxPubSize     = 32 // x25519 public key
	NonceSize      = 24 // xsalsa20 nonce used by secretbox
	SigSize        = 64 // ed25519 signature
	WrappedKeySize = 80 // 32-byte message key + box.AnonymousOverhead (48)

	// MaxNameLen bounds a nickname. Unbounded strings from the network are how
	// you end up printing a megabyte of someone else's choosing to a terminal.
	MaxNameLen = 24

	// MaxIDsPerList caps a HAVE/WANT digest so it always fits one datagram.
	MaxIDsPerList = 64
)

// Decoding errors. They are sentinel values so callers (and tests) can match on
// the specific failure with errors.Is.
var (
	ErrShortFrame = errors.New("codec: datagram shorter than frame header")
	ErrBadMagic   = errors.New("codec: not a gossip-mesh frame")
	ErrVersion    = errors.New("codec: unsupported protocol version")
	ErrLength     = errors.New("codec: declared body length does not match datagram")
	ErrTooLarge   = errors.New("codec: message would exceed one datagram")
	ErrTruncated  = errors.New("codec: message body ended early")
	ErrTrailing   = errors.New("codec: unexpected trailing bytes")
	ErrFieldSize  = errors.New("codec: field has the wrong length")
	ErrTooManyIDs = errors.New("codec: too many message ids for one datagram")
)

// MsgType identifies what a frame carries.
type MsgType uint8

const (
	// TypeHello is the presence beacon: "I exist, here are my keys and port."
	TypeHello MsgType = 1
	// TypeChat is one signed, encrypted chat message, relayed verbatim.
	TypeChat MsgType = 2
	// TypeHave advertises which message ids a node holds (anti-entropy push).
	TypeHave MsgType = 3
	// TypeWant asks for specific message ids (anti-entropy pull).
	TypeWant MsgType = 4
)

func (t MsgType) String() string {
	switch t {
	case TypeHello:
		return "HELLO"
	case TypeChat:
		return "CHAT"
	case TypeHave:
		return "HAVE"
	case TypeWant:
		return "WANT"
	default:
		return fmt.Sprintf("TYPE(%d)", uint8(t))
	}
}

// EncodeFrame wraps a marshalled body in the outer frame.
func EncodeFrame(t MsgType, body []byte) ([]byte, error) {
	if len(body) > MaxBodySize {
		return nil, fmt.Errorf("%w: %s body is %d bytes, limit %d", ErrTooLarge, t, len(body), MaxBodySize)
	}
	out := make([]byte, HeaderSize+len(body))
	copy(out[0:4], Magic)
	out[4] = Version
	out[5] = byte(t)
	binary.BigEndian.PutUint32(out[6:10], uint32(len(body)))
	copy(out[HeaderSize:], body)
	return out, nil
}

// DecodeFrame validates the outer frame and returns the body.
//
// The returned slice aliases p, so callers must not hold onto it after the read
// buffer is reused. Every Unmarshal function below copies what it keeps.
func DecodeFrame(p []byte) (MsgType, []byte, error) {
	if len(p) < HeaderSize {
		return 0, nil, ErrShortFrame
	}
	if string(p[0:4]) != Magic {
		return 0, nil, ErrBadMagic
	}
	if p[4] != Version {
		return 0, nil, fmt.Errorf("%w: got %d, want %d", ErrVersion, p[4], Version)
	}

	// One datagram carries exactly one frame, so the declared length must match
	// what actually arrived. Insisting on equality (rather than "at least")
	// means a lying header is rejected here instead of causing a strange
	// failure deeper in the parser.
	declared := int(binary.BigEndian.Uint32(p[6:10]))
	if declared != len(p)-HeaderSize {
		return 0, nil, fmt.Errorf("%w: declared %d, have %d", ErrLength, declared, len(p)-HeaderSize)
	}
	return MsgType(p[5]), p[HeaderSize:], nil
}

// Hello is the presence beacon, multicast every couple of seconds.
//
// It is signed, which is what binds the encryption key to the identity: without
// that signature an attacker could announce their own BoxPub under someone
// else's name and be sent readable messages.
type Hello struct {
	Name     string
	SignPub  []byte // SignPubSize
	BoxPub   []byte // BoxPubSize
	DataPort uint16 // where to send unicast replies
	TS       int64  // unix milliseconds, checked for freshness on receipt
	Sig      []byte // SigSize, over SigningBytes()
}

// SigningBytes returns everything except the signature: the exact bytes the
// sender signs and the receiver verifies.
func (h *Hello) SigningBytes() ([]byte, error) { return h.marshal(false) }

// Marshal returns the full body including the signature.
func (h *Hello) Marshal() ([]byte, error) { return h.marshal(true) }

func (h *Hello) marshal(withSig bool) ([]byte, error) {
	if len(h.Name) == 0 || len(h.Name) > MaxNameLen {
		return nil, fmt.Errorf("%w: name is %d bytes, want 1..%d", ErrFieldSize, len(h.Name), MaxNameLen)
	}
	if len(h.SignPub) != SignPubSize || len(h.BoxPub) != BoxPubSize {
		return nil, fmt.Errorf("%w: hello keys", ErrFieldSize)
	}
	if withSig && len(h.Sig) != SigSize {
		return nil, fmt.Errorf("%w: hello signature", ErrFieldSize)
	}

	w := &writer{}
	w.blob16([]byte(h.Name))
	w.raw(h.SignPub)
	w.raw(h.BoxPub)
	w.u16(h.DataPort)
	w.i64(h.TS)
	if withSig {
		w.raw(h.Sig)
	}
	return w.b, nil
}

// UnmarshalHello parses a HELLO body. It does not check the signature; that is
// the crypto package's job, which keeps "how bytes are laid out" separate from
// "how bytes are trusted".
func UnmarshalHello(b []byte) (*Hello, error) {
	r := &reader{b: b}

	name := r.blob16()
	signPub := r.raw(SignPubSize)
	boxPub := r.raw(BoxPubSize)
	port := r.u16()
	ts := r.i64()
	sig := r.raw(SigSize)
	if err := r.finish(); err != nil {
		return nil, err
	}
	if len(name) == 0 || len(name) > MaxNameLen {
		return nil, fmt.Errorf("%w: hello name is %d bytes", ErrFieldSize, len(name))
	}

	return &Hello{
		Name:     SanitizeLine(string(name)),
		SignPub:  clone(signPub),
		BoxPub:   clone(boxPub),
		DataPort: port,
		TS:       ts,
		Sig:      clone(sig),
	}, nil
}

// Recipient is one wrapped copy of a message key.
//
// FP is only the first 8 bytes of a fingerprint, and it is a lookup hint, not a
// security check: it lets a recipient find its own wrapped key without trying
// to decrypt all of them. Authenticity still comes from the sealed box opening
// successfully.
type Recipient struct {
	FP         [FPSize]byte
	WrappedKey []byte // WrappedKeySize
}

// Chat is a single chat message as it appears on the wire. Relays forward these
// byte-for-byte, including ones they cannot decrypt.
type Chat struct {
	ID            [IDSize]byte
	TS            int64
	SenderSignPub []byte // SignPubSize
	Nonce         [NonceSize]byte
	Recipients    []Recipient
	Ciphertext    []byte
	Sig           []byte // SigSize
}

// SigningBytes returns the bytes covered by the signature.
//
// Note that this includes the recipient list. That is deliberate: relays
// forward messages they cannot read, so if the wrapped keys were left unsigned
// a malicious relay could strip a recipient — silently censoring one specific
// person — or splice in its own. Covering them makes any such edit detectable.
func (c *Chat) SigningBytes() ([]byte, error) { return c.marshal(false) }

// Marshal returns the full body including the signature.
func (c *Chat) Marshal() ([]byte, error) { return c.marshal(true) }

func (c *Chat) marshal(withSig bool) ([]byte, error) {
	if len(c.SenderSignPub) != SignPubSize {
		return nil, fmt.Errorf("%w: chat sender key", ErrFieldSize)
	}
	if len(c.Recipients) > 255 {
		return nil, fmt.Errorf("%w: %d recipients", ErrTooLarge, len(c.Recipients))
	}
	if withSig && len(c.Sig) != SigSize {
		return nil, fmt.Errorf("%w: chat signature", ErrFieldSize)
	}
	for _, rcpt := range c.Recipients {
		if len(rcpt.WrappedKey) != WrappedKeySize {
			return nil, fmt.Errorf("%w: wrapped key is %d bytes, want %d", ErrFieldSize, len(rcpt.WrappedKey), WrappedKeySize)
		}
	}

	w := &writer{}
	w.raw(c.ID[:])
	w.i64(c.TS)
	w.raw(c.SenderSignPub)
	w.raw(c.Nonce[:])
	w.u8(uint8(len(c.Recipients)))
	for _, rcpt := range c.Recipients {
		w.raw(rcpt.FP[:])
		w.raw(rcpt.WrappedKey)
	}
	w.blob16(c.Ciphertext)
	if withSig {
		w.raw(c.Sig)
	}
	return w.b, nil
}

// UnmarshalChat parses a CHAT body, copying every field it keeps so the result
// stays valid after the caller's read buffer is reused.
func UnmarshalChat(b []byte) (*Chat, error) {
	c := &Chat{}
	r := &reader{b: b}

	copy(c.ID[:], r.raw(IDSize))
	c.TS = r.i64()
	c.SenderSignPub = clone(r.raw(SignPubSize))
	copy(c.Nonce[:], r.raw(NonceSize))

	n := int(r.u8())
	// Bail out before allocating: with a truncated packet a lying count would
	// otherwise make us reserve capacity for recipients that are not there.
	if r.err == nil && HeaderSize+n*(FPSize+WrappedKeySize) > MaxDatagram {
		return nil, fmt.Errorf("%w: %d recipients", ErrTooLarge, n)
	}
	if n > 0 {
		c.Recipients = make([]Recipient, 0, n)
	}
	for i := 0; i < n; i++ {
		var rcpt Recipient
		copy(rcpt.FP[:], r.raw(FPSize))
		rcpt.WrappedKey = clone(r.raw(WrappedKeySize))
		if r.err != nil {
			return nil, r.err
		}
		c.Recipients = append(c.Recipients, rcpt)
	}

	c.Ciphertext = clone(r.blob16())
	c.Sig = clone(r.raw(SigSize))
	if err := r.finish(); err != nil {
		return nil, err
	}
	return c, nil
}

// IDList is the body of both HAVE and WANT: just a list of message ids. The two
// messages share a shape because they are two halves of the same conversation
// ("here is what I hold" / "send me these").
type IDList struct {
	IDs [][IDSize]byte
}

// Marshal encodes the id list.
func (l *IDList) Marshal() ([]byte, error) {
	if len(l.IDs) > MaxIDsPerList {
		return nil, fmt.Errorf("%w: %d ids, limit %d", ErrTooManyIDs, len(l.IDs), MaxIDsPerList)
	}
	w := &writer{}
	w.u16(uint16(len(l.IDs)))
	for _, id := range l.IDs {
		w.raw(id[:])
	}
	return w.b, nil
}

// UnmarshalIDList parses a HAVE or WANT body.
func UnmarshalIDList(b []byte) (*IDList, error) {
	r := &reader{b: b}
	n := int(r.u16())
	if r.err != nil {
		return nil, r.err
	}
	if n > MaxIDsPerList {
		return nil, fmt.Errorf("%w: %d ids, limit %d", ErrTooManyIDs, n, MaxIDsPerList)
	}

	l := &IDList{}
	if n > 0 {
		l.IDs = make([][IDSize]byte, 0, n)
	}
	for i := 0; i < n; i++ {
		var id [IDSize]byte
		copy(id[:], r.raw(IDSize))
		if r.err != nil {
			return nil, r.err
		}
		l.IDs = append(l.IDs, id)
	}
	if err := r.finish(); err != nil {
		return nil, err
	}
	return l, nil
}

// SanitizeLine strips control characters from text that came off the network
// before it is printed.
//
// This is not paranoia: a peer chooses its own nickname and message text, and
// raw bytes written to a terminal can contain ANSI escape sequences that move
// the cursor, clear the screen, or in some terminals worse. Anything that
// reaches the user's screen from an untrusted source gets flattened first.
func SanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r == unicode.ReplacementChar:
			return -1
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, strings.ToValidUTF8(s, ""))
}

func clone(p []byte) []byte {
	if p == nil {
		return nil
	}
	out := make([]byte, len(p))
	copy(out, p)
	return out
}

// writer appends fields in big-endian order. Big-endian ("network byte order")
// is the convention for wire formats and makes hex dumps readable left to right.
type writer struct{ b []byte }

func (w *writer) raw(p []byte) { w.b = append(w.b, p...) }
func (w *writer) u8(v uint8)   { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) i64(v int64)  { w.b = binary.BigEndian.AppendUint64(w.b, uint64(v)) }
func (w *writer) blob16(p []byte) {
	w.u16(uint16(len(p)))
	w.raw(p)
}

// reader is the mirror image, with one important property: once it hits a
// problem it latches the error and every later call is a no-op returning zero
// values. That means the parsing code above can read a whole message as
// straight-line code and check for failure once at the end, instead of an error
// check after every field.
type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) raw(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = fmt.Errorf("%w: wanted %d bytes at offset %d of %d", ErrTruncated, n, r.off, len(r.b))
		return nil
	}
	p := r.b[r.off : r.off+n]
	r.off += n
	return p
}

func (r *reader) u8() uint8 {
	p := r.raw(1)
	if p == nil {
		return 0
	}
	return p[0]
}

func (r *reader) u16() uint16 {
	p := r.raw(2)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint16(p)
}

func (r *reader) i64() int64 {
	p := r.raw(8)
	if p == nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(p))
}

func (r *reader) blob16() []byte { return r.raw(int(r.u16())) }

// finish reports any latched error, and also rejects leftover bytes. Refusing
// to ignore trailing data means a peer cannot smuggle extra content past the
// signature check by appending it to an otherwise valid message.
func (r *reader) finish() error {
	if r.err != nil {
		return r.err
	}
	if r.off != len(r.b) {
		return fmt.Errorf("%w: %d bytes left over", ErrTrailing, len(r.b)-r.off)
	}
	return nil
}
