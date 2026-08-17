package codec

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	body := []byte("hello body")

	frame, err := EncodeFrame(TypeChat, body)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}

	kind, got, err := DecodeFrame(frame)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if kind != TypeChat {
		t.Errorf("type = %v, want %v", kind, TypeChat)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body = %q, want %q", got, body)
	}
}

// A hostile peer chooses these bytes, so every one of these cases must produce
// an error rather than a panic or a silent misparse.
func TestDecodeFrameRejectsMalformed(t *testing.T) {
	valid, err := EncodeFrame(TypeHello, []byte("abcd"))
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}

	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"empty", nil, ErrShortFrame},
		{"header only truncated", valid[:HeaderSize-1], ErrShortFrame},
		{"bad magic", append([]byte("XXXX"), valid[4:]...), ErrBadMagic},
		{"body shorter than declared", valid[:len(valid)-1], ErrLength},
		{"body longer than declared", append(bytes.Clone(valid), 0x00), ErrLength},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := DecodeFrame(tc.frame); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("wrong version", func(t *testing.T) {
		bad := bytes.Clone(valid)
		bad[4] = Version + 1
		if _, _, err := DecodeFrame(bad); !errors.Is(err, ErrVersion) {
			t.Fatalf("err = %v, want %v", err, ErrVersion)
		}
	})
}

func TestEncodeFrameRejectsOversizedBody(t *testing.T) {
	if _, err := EncodeFrame(TypeChat, make([]byte, MaxBodySize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want %v", err, ErrTooLarge)
	}
}

func TestHelloRoundTrip(t *testing.T) {
	want := &Hello{
		Name:     "alice",
		SignPub:  bytes.Repeat([]byte{1}, SignPubSize),
		BoxPub:   bytes.Repeat([]byte{2}, BoxPubSize),
		DataPort: 54321,
		TS:       1723900000000,
		Sig:      bytes.Repeat([]byte{3}, SigSize),
	}

	body, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalHello(body)
	if err != nil {
		t.Fatalf("UnmarshalHello: %v", err)
	}

	if got.Name != want.Name || got.DataPort != want.DataPort || got.TS != want.TS {
		t.Errorf("scalar fields differ: %+v", got)
	}
	if !bytes.Equal(got.SignPub, want.SignPub) || !bytes.Equal(got.BoxPub, want.BoxPub) || !bytes.Equal(got.Sig, want.Sig) {
		t.Error("key or signature bytes differ")
	}

	// SigningBytes must be a strict prefix of the full body, or the receiver
	// would be verifying different bytes than the sender signed.
	signing, err := want.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if !bytes.Equal(body[:len(signing)], signing) || len(body)-len(signing) != SigSize {
		t.Error("SigningBytes is not the body minus the signature")
	}
}

func TestChatRoundTrip(t *testing.T) {
	want := &Chat{
		TS:            1723900000000,
		SenderSignPub: bytes.Repeat([]byte{7}, SignPubSize),
		Ciphertext:    []byte("not really ciphertext"),
		Sig:           bytes.Repeat([]byte{9}, SigSize),
	}
	copy(want.ID[:], bytes.Repeat([]byte{4}, IDSize))
	copy(want.Nonce[:], bytes.Repeat([]byte{5}, NonceSize))
	for i := 0; i < 3; i++ {
		rcpt := Recipient{WrappedKey: bytes.Repeat([]byte{byte(i)}, WrappedKeySize)}
		copy(rcpt.FP[:], bytes.Repeat([]byte{byte(i + 100)}, FPSize))
		want.Recipients = append(want.Recipients, rcpt)
	}

	body, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalChat(body)
	if err != nil {
		t.Fatalf("UnmarshalChat: %v", err)
	}

	if got.ID != want.ID || got.TS != want.TS || got.Nonce != want.Nonce {
		t.Error("fixed fields differ")
	}
	if len(got.Recipients) != len(want.Recipients) {
		t.Fatalf("recipients = %d, want %d", len(got.Recipients), len(want.Recipients))
	}
	for i := range got.Recipients {
		if got.Recipients[i].FP != want.Recipients[i].FP {
			t.Errorf("recipient %d fingerprint differs", i)
		}
		if !bytes.Equal(got.Recipients[i].WrappedKey, want.Recipients[i].WrappedKey) {
			t.Errorf("recipient %d wrapped key differs", i)
		}
	}
	if !bytes.Equal(got.Ciphertext, want.Ciphertext) {
		t.Error("ciphertext differs")
	}
}

// A decoded message must not alias the caller's read buffer, because that buffer
// is reused for the next packet. If this ever regresses, messages would appear
// to mutate at random under load, which is a miserable bug to chase.
func TestUnmarshalChatCopiesItsInput(t *testing.T) {
	original := &Chat{
		TS:            1723900000000,
		SenderSignPub: bytes.Repeat([]byte{7}, SignPubSize),
		Ciphertext:    []byte("secret"),
		Sig:           bytes.Repeat([]byte{9}, SigSize),
	}
	body, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	buf := bytes.Clone(body)
	got, err := UnmarshalChat(buf)
	if err != nil {
		t.Fatalf("UnmarshalChat: %v", err)
	}

	for i := range buf { // simulate the next datagram landing in the buffer
		buf[i] = 0xff
	}
	if !bytes.Equal(got.Ciphertext, []byte("secret")) {
		t.Errorf("ciphertext aliased the read buffer: %q", got.Ciphertext)
	}
}

func TestUnmarshalChatRejectsTruncated(t *testing.T) {
	full := &Chat{
		TS:            1723900000000,
		SenderSignPub: bytes.Repeat([]byte{7}, SignPubSize),
		Ciphertext:    []byte("body"),
		Sig:           bytes.Repeat([]byte{9}, SigSize),
	}
	body, err := full.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	for cut := 1; cut < len(body); cut++ {
		if _, err := UnmarshalChat(body[:len(body)-cut]); err == nil {
			t.Fatalf("truncating %d bytes was accepted", cut)
		}
	}
}

// A lying recipient count must not make us allocate for data that is not there.
func TestUnmarshalChatRejectsInflatedRecipientCount(t *testing.T) {
	c := &Chat{
		TS:            1,
		SenderSignPub: bytes.Repeat([]byte{7}, SignPubSize),
		Sig:           bytes.Repeat([]byte{9}, SigSize),
	}
	body, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	countOffset := IDSize + 8 + SignPubSize + NonceSize
	body[countOffset] = 255
	if _, err := UnmarshalChat(body); err == nil {
		t.Fatal("inflated recipient count was accepted")
	}
}

func TestIDListRoundTrip(t *testing.T) {
	want := &IDList{}
	for i := 0; i < 5; i++ {
		var id [IDSize]byte
		id[0] = byte(i)
		want.IDs = append(want.IDs, id)
	}

	body, err := want.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalIDList(body)
	if err != nil {
		t.Fatalf("UnmarshalIDList: %v", err)
	}
	if len(got.IDs) != len(want.IDs) {
		t.Fatalf("ids = %d, want %d", len(got.IDs), len(want.IDs))
	}
	for i := range got.IDs {
		if got.IDs[i] != want.IDs[i] {
			t.Errorf("id %d differs", i)
		}
	}

	// A digest of the maximum size must still fit one datagram.
	max := &IDList{IDs: make([][IDSize]byte, MaxIDsPerList)}
	body, err = max.Marshal()
	if err != nil {
		t.Fatalf("Marshal max: %v", err)
	}
	if HeaderSize+len(body) > MaxDatagram {
		t.Errorf("full digest frame is %d bytes, over the %d limit", HeaderSize+len(body), MaxDatagram)
	}
}

func TestIDListRejectsTooMany(t *testing.T) {
	l := &IDList{IDs: make([][IDSize]byte, MaxIDsPerList+1)}
	if _, err := l.Marshal(); !errors.Is(err, ErrTooManyIDs) {
		t.Fatalf("err = %v, want %v", err, ErrTooManyIDs)
	}
}

// Text from the network reaches a terminal, so control characters and escape
// sequences must not survive the trip.
func TestSanitizeLine(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"clear\x1b[2Jscreen", "clear[2Jscreen"},
		{"two\nlines", "twolines"},
		{"tab\there", "tab here"},
		{"null\x00byte", "nullbyte"},
		{"unicode ok \u00e9\u00fc", "unicode ok \u00e9\u00fc"},
	}
	for _, tc := range tests {
		if got := SanitizeLine(tc.in); got != tc.want {
			t.Errorf("SanitizeLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := SanitizeLine(string([]byte{0xff, 0xfe})); strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("invalid UTF-8 leaked a replacement char: %q", got)
	}
}
