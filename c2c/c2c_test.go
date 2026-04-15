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

func TestRoundtrip(t *testing.T) {
	c, err := NewCodec(randKey(t), &novaproto.Options{
		PadTo:     64,
		PadMax:    16,
		PrefixMax: 8,
	})
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	if c.GetMagic() != novaproto.Magic {
		t.Errorf("magic: got %#x, want %#x", c.GetMagic(), novaproto.Magic)
	}
	if c.GetVersion() != novaproto.Version {
		t.Errorf("version: got %d, want %d", c.GetVersion(), novaproto.Version)
	}

	pkt := &NovaPacket{
		Header:  Header{FragmentNum: 2, FragmentsCount: 5},
		Meta:    Metadata{ContentType: 7},
		Payload: []byte("hello, c2c"),
	}
	frame, err := c.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := c.Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header != pkt.Header {
		t.Errorf("Header: got %+v, want %+v", got.Header, pkt.Header)
	}
	if got.Meta != pkt.Meta {
		t.Errorf("Meta: got %+v, want %+v", got.Meta, pkt.Meta)
	}
	if !bytes.Equal(got.Payload, pkt.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, pkt.Payload)
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
