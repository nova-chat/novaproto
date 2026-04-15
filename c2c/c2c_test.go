package c2c

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/nova-chat/novaproto"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func randParams(t *testing.T, encrypted bool) novaproto.HeaderParams {
	t.Helper()
	p := novaproto.HeaderParams{
		FragmentNum:    2,
		FragmentsCount: 5,
		IsEncrypted:    encrypted,
	}
	if _, err := rand.Read(p.Nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return p
}

func TestRoundtrip(t *testing.T) {
	c, err := NewCodec(randKey(t), &novaproto.Options{
		PadTo:     64,
		PadMax:    16,
		PrefixMax: 8,
	})
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	pkt := &NovaPacket{
		Meta:    Metadata{ContentType: 7},
		Payload: []byte("hello, c2c"),
	}
	params := randParams(t, true)

	frame, err := c.Encode(pkt, params)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, gotParams, err := c.Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if gotParams.FragmentNum != params.FragmentNum ||
		gotParams.FragmentsCount != params.FragmentsCount ||
		gotParams.IsEncrypted != params.IsEncrypted {
		t.Errorf("params: got %+v, want %+v", gotParams, params)
	}
	if gotParams.Nonce != params.Nonce {
		t.Errorf("nonce mismatch: got %x, want %x", gotParams.Nonce, params.Nonce)
	}
	if got.Meta != pkt.Meta {
		t.Errorf("Meta: got %+v, want %+v", got.Meta, pkt.Meta)
	}
	if !bytes.Equal(got.Payload, pkt.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, pkt.Payload)
	}
}

func TestPlainRoundtrip(t *testing.T) {
	c, err := NewCodec(randKey(t), nil)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	pkt := &NovaPacket{
		Meta:    Metadata{ContentType: 9},
		Payload: []byte("hello, plain c2c"),
	}
	frame, err := c.Encode(pkt, novaproto.HeaderParams{IsEncrypted: false, FragmentsCount: 1})
	if err != nil {
		t.Fatalf("Encode plain: %v", err)
	}
	if frame[0] != 0 {
		t.Errorf("plain flag byte: got %#x, want 0", frame[0])
	}
	got, params, err := c.Decode(frame)
	if err != nil {
		t.Fatalf("Decode plain: %v", err)
	}
	if params.IsEncrypted {
		t.Error("decoded IsEncrypted should be false")
	}
	if got.Meta != pkt.Meta || !bytes.Equal(got.Payload, pkt.Payload) {
		t.Errorf("plain roundtrip mismatch: meta=%+v payload=%q", got.Meta, got.Payload)
	}
}

func TestTamperRejected(t *testing.T) {
	c, err := NewCodec(randKey(t), nil)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	frame, err := c.Encode(&NovaPacket{
		Meta:    Metadata{ContentType: 1},
		Payload: []byte("secret"),
	}, randParams(t, true))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := c.Decode(tampered); err == nil {
		t.Error("Decode accepted tampered frame")
	}
}
