package dhellman

import (
	"bytes"
	"testing"

	"github.com/nova-chat/novaproto/serializer"
)

func TestHandshakeRoundtrip(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("alice GenerateKeyPair: %v", err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("bob GenerateKeyPair: %v", err)
	}

	aliceHello := NewHelloMessage(alice)
	bobHello := NewHelloMessage(bob)

	aliceWire, err := serializer.Marshal(aliceHello)
	if err != nil {
		t.Fatalf("alice Marshal: %v", err)
	}
	bobWire, err := serializer.Marshal(bobHello)
	if err != nil {
		t.Fatalf("bob Marshal: %v", err)
	}

	var gotBob HelloMessage
	if err := serializer.Unmarshal(bobWire, &gotBob); err != nil {
		t.Fatalf("alice Unmarshal: %v", err)
	}
	if gotBob.Version != HelloVersion {
		t.Fatalf("gotBob version: got %d, want %d", gotBob.Version, HelloVersion)
	}
	var gotAlice HelloMessage
	if err := serializer.Unmarshal(aliceWire, &gotAlice); err != nil {
		t.Fatalf("bob Unmarshal: %v", err)
	}
	if gotAlice.Version != HelloVersion {
		t.Fatalf("gotAlice version: got %d, want %d", gotAlice.Version, HelloVersion)
	}

	aliceShared, err := alice.ComputeShared(gotBob.PublicKey)
	if err != nil {
		t.Fatalf("alice ComputeShared: %v", err)
	}
	bobShared, err := bob.ComputeShared(gotAlice.PublicKey)
	if err != nil {
		t.Fatalf("bob ComputeShared: %v", err)
	}
	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("shared secrets differ")
	}

	salt := append(append([]byte{}, aliceHello.PublicKey[:]...), bobHello.PublicKey[:]...)
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
