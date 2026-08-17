package crypto

import (
	"errors"
	"strings"
	"testing"
	"time"

	"gossipmesh/internal/codec"
	"gossipmesh/internal/identity"
)

func newIdentity(t *testing.T, name string) *identity.Identity {
	t.Helper()
	id, err := identity.Generate(name)
	if err != nil {
		t.Fatalf("Generate(%q): %v", name, err)
	}
	return id
}

func recipientOf(id *identity.Identity) Recipient {
	return Recipient{FP: id.Fingerprint(), BoxPub: id.BoxPub}
}

// The wire format hard-codes the size of a wrapped key, so if the crypto library
// ever changed its overhead, every packet would be silently malformed. Assert the
// two agree.
func TestWrappedKeySizeMatchesWireFormat(t *testing.T) {
	if got := identity.SealedSize(messageKeySize); got != codec.WrappedKeySize {
		t.Fatalf("sealed 32-byte key is %d bytes, but codec.WrappedKeySize is %d", got, codec.WrappedKeySize)
	}
}

// The full send/receive path, exactly as two nodes would do it over UDP.
func TestChatEndToEnd(t *testing.T) {
	alice := newIdentity(t, "alice")
	bob := newIdentity(t, "bob")

	_, frame, err := BuildChat(alice, "meet at the docks", []Recipient{recipientOf(alice), recipientOf(bob)})
	if err != nil {
		t.Fatalf("BuildChat: %v", err)
	}

	kind, body, err := codec.DecodeFrame(frame)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if kind != codec.TypeChat {
		t.Fatalf("kind = %v, want CHAT", kind)
	}
	chat, err := codec.UnmarshalChat(body)
	if err != nil {
		t.Fatalf("UnmarshalChat: %v", err)
	}
	if err := VerifyChat(chat); err != nil {
		t.Fatalf("VerifyChat: %v", err)
	}

	// Both addressed parties can read it, including the sender itself.
	for _, id := range []*identity.Identity{alice, bob} {
		text, ok := OpenChat(chat, id)
		if !ok {
			t.Fatalf("%s could not open the message", id.Name)
		}
		if text != "meet at the docks" {
			t.Errorf("%s read %q", id.Name, text)
		}
	}

	// A third party on the same LAN, who was not a recipient, cannot.
	if _, ok := OpenChat(chat, newIdentity(t, "eve")); ok {
		t.Error("a non-recipient decrypted the message")
	}
}

func TestChatFitsOneDatagramAtFullCapacity(t *testing.T) {
	sender := newIdentity(t, "sender")

	recipients := []Recipient{recipientOf(sender)}
	for i := 1; i < MaxRecipients; i++ {
		recipients = append(recipients, recipientOf(newIdentity(t, "peer")))
	}

	_, frame, err := BuildChat(sender, strings.Repeat("x", MaxTextBytes), recipients)
	if err != nil {
		t.Fatalf("BuildChat: %v", err)
	}
	if len(frame) > codec.MaxDatagram {
		t.Fatalf("worst-case frame is %d bytes, over the %d budget", len(frame), codec.MaxDatagram)
	}
	t.Logf("worst case: %d recipients, %d bytes of text, %d byte datagram", len(recipients), MaxTextBytes, len(frame))
}

func TestVerifyChatRejectsForgery(t *testing.T) {
	alice := newIdentity(t, "alice")
	bob := newIdentity(t, "bob")

	build := func(t *testing.T) *codec.Chat {
		t.Helper()
		chat, _, err := BuildChat(alice, "original text", []Recipient{recipientOf(alice), recipientOf(bob)})
		if err != nil {
			t.Fatalf("BuildChat: %v", err)
		}
		return chat
	}

	t.Run("altered ciphertext", func(t *testing.T) {
		chat := build(t)
		chat.Ciphertext[0] ^= 0xff
		if err := VerifyChat(chat); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want %v", err, ErrBadSignature)
		}
	})

	// This is the case that motivated signing the recipient list: a relay that
	// drops a recipient would otherwise silently censor that one person.
	t.Run("recipient removed by a relay", func(t *testing.T) {
		chat := build(t)
		chat.Recipients = chat.Recipients[:1]
		if err := VerifyChat(chat); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want %v", err, ErrBadSignature)
		}
	})

	t.Run("wrapped key swapped", func(t *testing.T) {
		chat := build(t)
		chat.Recipients[1].WrappedKey[0] ^= 0xff
		if err := VerifyChat(chat); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want %v", err, ErrBadSignature)
		}
	})

	// An attacker who signs with their own key cannot borrow someone else's
	// identity, because the fingerprint follows the key that signed.
	t.Run("impostor claims another key", func(t *testing.T) {
		chat := build(t)
		chat.SenderSignPub = bob.SignPub
		if err := VerifyChat(chat); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want %v", err, ErrBadSignature)
		}
	})
}

// A captured message replayed hours later still has a valid signature, because
// signatures never expire. The freshness window is what rejects it.
func TestVerifyChatRejectsReplay(t *testing.T) {
	alice := newIdentity(t, "alice")

	chat, _, err := BuildChat(alice, "yesterday's news", []Recipient{recipientOf(alice)})
	if err != nil {
		t.Fatalf("BuildChat: %v", err)
	}

	chat.TS = time.Now().Add(-2 * ClockSkew).UnixMilli()
	signing, err := chat.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	chat.Sig = alice.Sign(signing) // a correctly signed, but stale, message

	if err := VerifyChat(chat); !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want %v", err, ErrStale)
	}
}

func TestBuildChatValidatesInput(t *testing.T) {
	alice := newIdentity(t, "alice")
	self := []Recipient{recipientOf(alice)}

	tests := []struct {
		name       string
		text       string
		recipients []Recipient
		want       error
	}{
		{"empty", "", self, ErrEmptyText},
		{"only control characters", "\x00\x1b", self, ErrEmptyText},
		{"too long", strings.Repeat("x", MaxTextBytes+1), self, ErrTextTooLong},
		{"no recipients", "hi", nil, ErrNoRecipients},
		{"too many recipients", "hi", make([]Recipient, MaxRecipients+1), ErrTooManyRcpts},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := BuildChat(alice, tc.text, tc.recipients); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestHelloSignedAndVerified(t *testing.T) {
	alice := newIdentity(t, "alice")

	frame, err := BuildHello(alice, 54321)
	if err != nil {
		t.Fatalf("BuildHello: %v", err)
	}
	_, body, err := codec.DecodeFrame(frame)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}

	hello, err := ParseHello(body)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}
	if hello.Name != "alice" || hello.DataPort != 54321 {
		t.Errorf("hello = %+v", hello)
	}
	if identity.FingerprintOf(hello.SignPub) != alice.Fingerprint() {
		t.Error("fingerprint does not match the sender")
	}

	// The attack this prevents: announcing your own encryption key under someone
	// else's name, so that peers encrypt to you.
	t.Run("substituted encryption key", func(t *testing.T) {
		eve := newIdentity(t, "eve")
		forged := &codec.Hello{
			Name:     hello.Name,
			SignPub:  hello.SignPub,
			BoxPub:   eve.BoxPub[:],
			DataPort: hello.DataPort,
			TS:       hello.TS,
			Sig:      hello.Sig,
		}
		forgedBody, err := forged.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if _, err := ParseHello(forgedBody); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("err = %v, want %v", err, ErrBadSignature)
		}
	})
}
