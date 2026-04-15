package c2s

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/google/uuid"

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
		FragmentsCount: 1,
		IsEncrypted:    encrypted,
	}
	if encrypted {
		if _, err := rand.Read(p.Nonce[:]); err != nil {
			t.Fatalf("nonce: %v", err)
		}
	}
	return p
}

func TestRoundtrip(t *testing.T) {
	c, err := NewCodec(randKey(t), &novaproto.Options{
		PadTo:     128,
		PadMax:    32,
		PrefixMax: 16,
	})
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	pkt := &NovaServerPacket{
		Meta: Metadata{
			SenderID:    uuid.New(),
			TargetID:    uuid.New(),
			MessageType: 0,
			Timestamp:   1_700_000_000_000_000_000,
		},
		Payload: []byte("opaque inner blob"),
	}
	frame, err := c.Encode(pkt, randParams(t, true))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, params, err := c.Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !params.IsEncrypted {
		t.Error("decoded IsEncrypted should be true")
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
	pkt := &NovaServerPacket{
		Meta: Metadata{
			SenderID:    uuid.New(),
			TargetID:    uuid.New(),
			MessageType: 0,
			Timestamp:   1_700_000_000_000_000_000,
		},
		Payload: []byte("public handshake blob"),
	}
	frame, err := c.Encode(pkt, randParams(t, false))
	if err != nil {
		t.Fatalf("Encode plain: %v", err)
	}

	// Plain frames must carry Header.IsEncrypted=false at offset 0 so
	// first-byte dispatch works without a key. After the IsEncrypted byte
	// and the 12-byte Nonce, the shared novaproto.Magic sits at offset 13.
	if frame[0] != 0 {
		t.Errorf("wire IsEncrypted byte: got %#x, want 0", frame[0])
	}
	const magicOff = 1 + 12
	if magic := binary.BigEndian.Uint32(frame[magicOff : magicOff+4]); magic != novaproto.Magic {
		t.Errorf("wire magic: got %#x, want %#x", magic, novaproto.Magic)
	}
	// The plaintext payload must be readable on the wire.
	if !bytes.Contains(frame, pkt.Payload) {
		t.Error("plain frame should contain payload in the clear")
	}

	got, params, err := c.Decode(frame)
	if err != nil {
		t.Fatalf("Decode plain: %v", err)
	}
	if params.IsEncrypted {
		t.Error("decoded IsEncrypted should be false")
	}
	if got.Meta != pkt.Meta {
		t.Errorf("Meta: got %+v, want %+v", got.Meta, pkt.Meta)
	}
	if !bytes.Equal(got.Payload, pkt.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, pkt.Payload)
	}
}

// TestMixedStreamDispatch sends a random mix of plain and encrypted
// frames through a single Decode entry point and checks that each is
// dispatched correctly based on the IsEncrypted byte.
func TestMixedStreamDispatch(t *testing.T) {
	codec, err := NewCodec(randKey(t), nil)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	const iterations = 200
	plainCount, encCount := 0, 0

	for i := 0; i < iterations; i++ {
		pkt := &NovaServerPacket{
			Meta: Metadata{
				SenderID:    uuid.New(),
				TargetID:    uuid.New(),
				MessageType: uint32(i),
				Timestamp:   1_700_000_000_000_000_000 + int64(i),
			},
			Payload: bytes.Repeat([]byte{byte(i)}, 16+i%48),
		}

		var coin [1]byte
		if _, err := rand.Read(coin[:]); err != nil {
			t.Fatalf("coin flip: %v", err)
		}
		wantEncrypted := coin[0]&1 == 0

		frame, err := codec.Encode(pkt, randParams(t, wantEncrypted))
		if err != nil {
			t.Fatalf("[%d] encode: %v", i, err)
		}

		got, params, err := codec.Decode(frame)
		if err != nil {
			t.Fatalf("[%d] decode: %v", i, err)
		}
		if params.IsEncrypted != wantEncrypted {
			t.Fatalf("[%d] IsEncrypted: got %v, want %v", i, params.IsEncrypted, wantEncrypted)
		}
		if params.IsEncrypted {
			encCount++
		} else {
			plainCount++
		}

		if got.Meta != pkt.Meta {
			t.Errorf("[%d] meta mismatch: got %+v, want %+v", i, got.Meta, pkt.Meta)
		}
		if !bytes.Equal(got.Payload, pkt.Payload) {
			t.Errorf("[%d] payload mismatch", i)
		}
	}

	if plainCount == 0 || encCount == 0 {
		t.Errorf("coin flip degenerate: plain=%d encrypted=%d", plainCount, encCount)
	}
	t.Logf("dispatched %d plain, %d encrypted frames", plainCount, encCount)
}

func TestTamperRejected(t *testing.T) {
	c, err := NewCodec(randKey(t), nil)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	frame, err := c.Encode(&NovaServerPacket{
		Meta: Metadata{
			SenderID: uuid.New(),
			TargetID: uuid.New(),
		},
		Payload: []byte("inner"),
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
