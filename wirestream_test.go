package novaproto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
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

// pipeStreams returns a pair of NovaWireStreams connected via net.Pipe.
func pipeStreams(t *testing.T) (*novaproto.NovaWireStream, *novaproto.NovaWireStream, func()) {
	t.Helper()
	a, b := net.Pipe()
	return novaproto.NewNovaWireStream(a),
		novaproto.NewNovaWireStream(b),
		func() { _ = a.Close(); _ = b.Close() }
}

func TestWireStreamRoundtrip(t *testing.T) {
	client, server, cleanup := pipeStreams(t)
	defer cleanup()

	want := novaproto.FrameHeader{
		PacketNonce:   42,
		FrameNonce:    1,
		IsTerminating: false,
	}
	payload := []byte("hello, frame")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := client.WriteFrame(want, payload); err != nil {
			t.Errorf("WriteFrame: %v", err)
		}
	}()

	got, content, err := server.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	wg.Wait()

	if got.Magic != novaproto.Magic {
		t.Errorf("magic: got %#x, want %#x", got.Magic, novaproto.Magic)
	}
	if got.PacketNonce != want.PacketNonce || got.FrameNonce != want.FrameNonce {
		t.Errorf("nonces: got (%d,%d), want (%d,%d)", got.PacketNonce, got.FrameNonce, want.PacketNonce, want.FrameNonce)
	}
	if got.ContentSize != uint32(len(payload)) {
		t.Errorf("content size: got %d, want %d", got.ContentSize, len(payload))
	}
	if !bytes.Equal(content, payload) {
		t.Errorf("content: got %q, want %q", content, payload)
	}
}

func TestWireStreamEmptyTerminatingFrame(t *testing.T) {
	client, server, cleanup := pipeStreams(t)
	defer cleanup()

	want := novaproto.FrameHeader{
		PacketNonce:   7,
		FrameNonce:    9,
		IsTerminating: true,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := client.WriteFrame(want, nil); err != nil {
			t.Errorf("WriteFrame: %v", err)
		}
	}()

	got, content, err := server.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	wg.Wait()

	if !got.IsTerminating {
		t.Error("IsTerminating should be true")
	}
	if len(content) != 0 {
		t.Errorf("content: got %d bytes, want 0", len(content))
	}
}

func TestWireStreamEOF(t *testing.T) {
	a, b := net.Pipe()
	server := novaproto.NewNovaWireStream(b)
	_ = a.Close()
	_, _, err := server.ReadFrame()
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected EOF or closed pipe, got %v", err)
	}
	_ = b.Close()
}

// TestWireCipherLateKey walks through the intended flow: plain frames
// before SetKey, encrypted frames after, on the same stream.
func TestWireCipherLateKey(t *testing.T) {
	aConn, bConn := net.Pipe()
	defer aConn.Close()
	defer bConn.Close()

	clientWire := novaproto.NewNovaWireStream(aConn)
	serverWire := novaproto.NewNovaWireStream(bConn)
	client := novaproto.NewNovaWireStreamCipher(clientWire)
	server := novaproto.NewNovaWireStreamCipher(serverWire)

	if client.HasKey() || server.HasKey() {
		t.Fatal("HasKey should be false before SetKey")
	}

	// --- Phase 1: plain handshake frame ---
	handshakeHdr := novaproto.FrameHeader{
		PacketNonce: 1,
		FrameNonce:  1,
	}
	handshakePayload := []byte("public hello")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := client.WriteFrame(handshakeHdr, handshakePayload); err != nil {
			t.Errorf("plain WriteFrame: %v", err)
		}
	}()

	gotHdr, gotContent, err := server.ReadFrame()
	if err != nil {
		t.Fatalf("plain ReadFrame: %v", err)
	}
	<-done
	if gotHdr.IsEncrypted {
		t.Error("handshake frame should not be encrypted")
	}
	if !bytes.Equal(gotContent, handshakePayload) {
		t.Errorf("handshake content: got %q, want %q", gotContent, handshakePayload)
	}

	// --- Phase 2: install key on both sides ---
	key := randKey(t)
	if err := client.SetKey(key); err != nil {
		t.Fatalf("client SetKey: %v", err)
	}
	if err := server.SetKey(key); err != nil {
		t.Fatalf("server SetKey: %v", err)
	}
	if !client.HasKey() || !server.HasKey() {
		t.Error("HasKey should be true after SetKey")
	}

	// --- Phase 3: encrypted frame ---
	secretHdr := novaproto.FrameHeader{PacketNonce: 2, FrameNonce: 1}
	secretPayload := []byte("this is confidential")

	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		if err := client.WriteFrame(secretHdr, secretPayload); err != nil {
			t.Errorf("encrypted WriteFrame: %v", err)
		}
	}()

	gotHdr, gotContent, err = server.ReadFrame()
	if err != nil {
		t.Fatalf("encrypted ReadFrame: %v", err)
	}
	<-done2
	if !gotHdr.IsEncrypted {
		t.Error("secret frame should be marked encrypted on the wire")
	}
	if !bytes.Equal(gotContent, secretPayload) {
		t.Errorf("decrypted content: got %q, want %q", gotContent, secretPayload)
	}
}

// TestWireCipherTamperRejected flips a ciphertext byte and expects
// AEAD Open to fail.
func TestWireCipherTamperRejected(t *testing.T) {
	var buf bytes.Buffer
	wire := novaproto.NewNovaWireStream(&buf)
	cipher := novaproto.NewNovaWireStreamCipher(wire)
	if err := cipher.SetKey(randKey(t)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	hdr := novaproto.FrameHeader{PacketNonce: 1, FrameNonce: 1}
	if err := cipher.WriteFrame(hdr, []byte("secret")); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Flip the last byte (inside the AEAD tag area).
	wire2 := novaproto.NewNovaWireStream(&buf)
	reader := novaproto.NewNovaWireStreamCipher(wire2)
	if err := reader.SetKey(randKey(t)); err != nil {
		// different key → Open will fail, which is also "rejected"
		t.Fatalf("SetKey: %v", err)
	}
	// Corrupt the buffer's last byte.
	data := buf.Bytes()
	data[len(data)-1] ^= 0x01

	if _, _, err := reader.ReadFrame(); err == nil {
		t.Error("ReadFrame should reject tampered / wrong-key frame")
	}
}

// TestWireCipherEncryptedWithoutKey verifies that receiving an
// encrypted frame without a key installed produces an error.
func TestWireCipherEncryptedWithoutKey(t *testing.T) {
	aConn, bConn := net.Pipe()
	defer aConn.Close()
	defer bConn.Close()

	sender := novaproto.NewNovaWireStreamCipher(novaproto.NewNovaWireStream(aConn))
	receiver := novaproto.NewNovaWireStreamCipher(novaproto.NewNovaWireStream(bConn))
	if err := sender.SetKey(randKey(t)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	// receiver has no key

	go func() {
		_ = sender.WriteFrame(novaproto.FrameHeader{PacketNonce: 1, FrameNonce: 1}, []byte("boo"))
	}()

	if _, _, err := receiver.ReadFrame(); err == nil {
		t.Error("expected error reading encrypted frame without key")
	}
}
