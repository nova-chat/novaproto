package dhellman

import (
	"bytes"
	"testing"
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

	aliceHello, err := NewHelloMessage(alice)
	if err != nil {
		t.Fatalf("alice NewHelloMessage: %v", err)
	}
	bobHello, err := NewHelloMessage(bob)
	if err != nil {
		t.Fatalf("bob NewHelloMessage: %v", err)
	}

	aliceWire := aliceHello.Marshal()
	bobWire := bobHello.Marshal()

	gotBob, err := UnmarshalHello(bobWire)
	if err != nil {
		t.Fatalf("alice UnmarshalHello: %v", err)
	}
	gotAlice, err := UnmarshalHello(aliceWire)
	if err != nil {
		t.Fatalf("bob UnmarshalHello: %v", err)
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

	salt := append(append([]byte{}, aliceHello.Nonce[:]...), bobHello.Nonce[:]...)
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

func TestUnmarshalHelloRejectsBadInput(t *testing.T) {
	if _, err := UnmarshalHello(nil); err == nil {
		t.Error("accepted nil")
	}
	if _, err := UnmarshalHello(make([]byte, helloSize-1)); err == nil {
		t.Error("accepted short buffer")
	}
	bad := make([]byte, helloSize)
	bad[1] = 0xFF
	if _, err := UnmarshalHello(bad); err == nil {
		t.Error("accepted unknown version")
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
