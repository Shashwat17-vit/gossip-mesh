package identity

import (
	"bytes"
	"os"
	"testing"
)

// Persistence is what makes a fingerprint meaningful: if keys were regenerated
// on every start, a node would look like a brand-new stranger to its peers each
// time and comparing fingerprints out of band would prove nothing.
func TestLoadPersistsIdentityAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	first, created, err := Load(dir, "alice")
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if !created {
		t.Error("created = false on first run")
	}

	second, created, err := Load(dir, "alice")
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if created {
		t.Error("created = true when the key file already existed")
	}

	if first.Fingerprint() != second.Fingerprint() {
		t.Errorf("fingerprint changed across restart: %s -> %s", first.Fingerprint(), second.Fingerprint())
	}
	if !bytes.Equal(first.SignPub, second.SignPub) {
		t.Error("signing key changed across restart")
	}
	if first.BoxPub != second.BoxPub {
		t.Error("encryption key changed across restart")
	}

	// The restored identity must be able to use the private halves too, not just
	// report matching public ones.
	sig := second.Sign([]byte("hello"))
	if !Verify(first.SignPub, []byte("hello"), sig) {
		t.Error("a signature from the restored identity does not verify")
	}
}

func TestDifferentNamesGetDifferentKeys(t *testing.T) {
	dir := t.TempDir()

	alice, _, err := Load(dir, "alice")
	if err != nil {
		t.Fatalf("Load alice: %v", err)
	}
	bob, _, err := Load(dir, "bob")
	if err != nil {
		t.Fatalf("Load bob: %v", err)
	}

	if alice.Fingerprint() == bob.Fingerprint() {
		t.Fatal("two identities share a fingerprint")
	}
}

func TestSealAndUnseal(t *testing.T) {
	alice, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	bob, err := Generate("bob")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	secret := bytes.Repeat([]byte{0xab}, 32)
	sealed, err := Seal(&bob.BoxPub, secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) != SealedSize(len(secret)) {
		t.Errorf("sealed length = %d, want %d", len(sealed), SealedSize(len(secret)))
	}

	got, ok := bob.Unseal(sealed)
	if !ok {
		t.Fatal("bob could not open a box addressed to him")
	}
	if !bytes.Equal(got, secret) {
		t.Error("decrypted secret differs")
	}

	if _, ok := alice.Unseal(sealed); ok {
		t.Error("alice opened a box addressed to bob")
	}

	// Sealed boxes are authenticated, so tampering fails rather than decrypting
	// to garbage that the caller might then act on.
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0xff
	if _, ok := bob.Unseal(tampered); ok {
		t.Error("a tampered box opened successfully")
	}
}

func TestFingerprintIsDerivedFromSigningKey(t *testing.T) {
	alice, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if FingerprintOf(alice.SignPub) != alice.Fingerprint() {
		t.Error("FingerprintOf disagrees with Identity.Fingerprint")
	}
	if got := len(alice.Fingerprint().String()); got != FingerprintSize*2 {
		t.Errorf("fingerprint prints %d hex characters, want %d", got, FingerprintSize*2)
	}
}

func TestLoadRejectsCorruptKeyFile(t *testing.T) {
	tests := map[string]string{
		"wrong header":  "not-a-key-file\n",
		"missing box":   "gossipmesh-key-v1\nsign-seed " + hex64 + "\n",
		"short seed":    "gossipmesh-key-v1\nsign-seed abcd\nbox-priv " + hex64 + "\n",
		"bad hex":       "gossipmesh-key-v1\nsign-seed zz\nbox-priv " + hex64 + "\n",
		"unknown field": "gossipmesh-key-v1\nmystery value\n",
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(KeyPath(dir, "alice"), []byte(contents), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, _, err := Load(dir, "alice"); err == nil {
				t.Fatal("a corrupt key file was accepted")
			}
		})
	}
}

const hex64 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
