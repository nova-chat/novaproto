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
	frame, err := c.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := c.Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Meta != pkt.Meta {
		t.Errorf("Meta: got %+v, want %+v", got.Meta, pkt.Meta)
	}
	if !bytes.Equal(got.Payload, pkt.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, pkt.Payload)
	}
}

func TestPlainRoundtrip(t *testing.T) {
	pkt := &NovaServerPacket{
		Meta: Metadata{
			SenderID:    uuid.New(),
			TargetID:    uuid.New(),
			MessageType: 0,
			Timestamp:   1_700_000_000_000_000_000,
		},
		Payload: []byte("public handshake blob"),
	}
	frame, err := EncodePlain(pkt)
	if err != nil {
		t.Fatalf("EncodePlain: %v", err)
	}

	// Plain frames must carry FlagPlain at offset 0 so IsPlain-based
	// dispatch works without any Codec. The unified Header follows the
	// flag byte; its Nonce occupies the next 12 bytes (zeroed in plain
	// mode), so the shared novaproto.Magic sits at offset 1+12.
	if novaproto.Flag(frame[0]) != novaproto.FlagPlain {
		t.Errorf("wire flag: got %#x, want %#x", frame[0], byte(novaproto.FlagPlain))
	}
	const magicOff = 1 + 12
	if magic := binary.BigEndian.Uint32(frame[magicOff : magicOff+4]); magic != novaproto.Magic {
		t.Errorf("wire magic: got %#x, want %#x", magic, novaproto.Magic)
	}
	if !IsPlain(frame) {
		t.Error("IsPlain should return true for a plain frame")
	}
	// The plaintext payload must be readable on the wire.
	if !bytes.Contains(frame, pkt.Payload) {
		t.Error("plain frame should contain payload in the clear")
	}

	got, err := DecodePlain(frame)
	if err != nil {
		t.Fatalf("DecodePlain: %v", err)
	}
	if got.Meta != pkt.Meta {
		t.Errorf("Meta: got %+v, want %+v", got.Meta, pkt.Meta)
	}
	if !bytes.Equal(got.Payload, pkt.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, pkt.Payload)
	}
}

func TestPlainAndEncryptedDistinct(t *testing.T) {
	c, err := NewCodec(randKey(t), nil)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	pkt := &NovaServerPacket{
		Meta:    Metadata{SenderID: uuid.New(), TargetID: uuid.New()},
		Payload: []byte("x"),
	}

	encFrame, err := c.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	plainFrame, err := EncodePlain(pkt)
	if err != nil {
		t.Fatalf("EncodePlain: %v", err)
	}

	// Cross-decoding must fail — different wire formats.
	if _, err := DecodePlain(encFrame); err == nil {
		t.Error("DecodePlain accepted an encrypted frame")
	}
	if _, err := c.Decode(plainFrame); err == nil {
		t.Error("Decode accepted a plain frame")
	}
}

// TestMixedStreamDispatch simulates a receiver that gets a random mix of
// plain and encrypted frames and must dispatch each to the right decoder
// using only IsPlain.
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

		var frame []byte
		if wantEncrypted {
			frame, err = codec.Encode(pkt)
		} else {
			frame, err = EncodePlain(pkt)
		}
		if err != nil {
			t.Fatalf("[%d] encode: %v", i, err)
		}

		// Receiver side: has no prior knowledge of which mode was used.
		isPlain := IsPlain(frame)
		if isPlain == wantEncrypted {
			t.Fatalf("[%d] IsPlain wrong: wantEncrypted=%v, isPlain=%v",
				i, wantEncrypted, isPlain)
		}

		var got *NovaServerPacket
		if isPlain {
			got, err = DecodePlain(frame)
			plainCount++
		} else {
			got, err = codec.Decode(frame)
			encCount++
		}
		if err != nil {
			t.Fatalf("[%d] decode (isPlain=%v): %v", i, isPlain, err)
		}

		if got.Meta != pkt.Meta {
			t.Errorf("[%d] meta mismatch: got %+v, want %+v", i, got.Meta, pkt.Meta)
		}
		if !bytes.Equal(got.Payload, pkt.Payload) {
			t.Errorf("[%d] payload mismatch", i)
		}
	}

	// Sanity-check that both branches actually exercised — a ~1/2^200
	// chance of either counter being zero, basically impossible.
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
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := c.Decode(tampered); err == nil {
		t.Error("Decode accepted tampered frame")
	}
}
