package dhellman

import (
	"bytes"
	"testing"
)

// TestHandshakeRoundtrip walks both sides through the symmetric
// X25519 + HKDF flow without involving any wire-message wrapper —
// callers serialize PublicKey() bytes themselves now.
func TestHandshakeRoundtrip(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("alice GenerateKeyPair: %v", err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("bob GenerateKeyPair: %v", err)
	}

	alicePub := alice.PublicKey()
	bobPub := bob.PublicKey()

	aliceShared, err := alice.ComputeShared(bobPub)
	if err != nil {
		t.Fatalf("alice ComputeShared: %v", err)
	}
	bobShared, err := bob.ComputeShared(alicePub)
	if err != nil {
		t.Fatalf("bob ComputeShared: %v", err)
	}
	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("shared secrets differ")
	}

	salt := append(append([]byte{}, alicePub[:]...), bobPub[:]...)
	info := []byte("novaproto/dhellman/test")

	aliceKey, err := DeriveKey(aliceShared, salt, info)
	if err != nil {
		t.Fatalf("alice DeriveKey: %v", err)
	}
	bobKey, err := DeriveKey(bobShared, salt, info)
	if err != nil {
		t.Fatalf("bob DeriveKey: %v", err)
	}
	if !bytes.Equal(aliceKey, bobKey) {
		t.Fatal("derived keys differ")
	}
	if len(aliceKey) != SharedKeySize {
		t.Fatalf("derived key size: got %d, want %d", len(aliceKey), SharedKeySize)
	}
}

func TestComputeSharedRejectsBadPubKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	var zero [PublicKeySize]byte
	if _, err := kp.ComputeShared(zero); err == nil {
		t.Error("accepted all-zero peer pubkey")
	}
}

func TestDeriveKeyRejectsEmptyShared(t *testing.T) {
	if _, err := DeriveKey(nil, []byte("salt"), []byte("info")); err == nil {
		t.Error("expected error for empty shared secret")
	}
}
