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

// pipePacketStreams returns a pair of PacketStreams connected via
// net.Pipe. Callers get cleanup closures for each side.
func pipePacketStreams(t *testing.T) (*novaproto.PacketStream, *novaproto.PacketStream, func()) {
	t.Helper()
	a, b := net.Pipe()
	client := novaproto.NewPacketStream(novaproto.NewNovaWireStream(a))
	server := novaproto.NewPacketStream(novaproto.NewNovaWireStream(b))
	return client, server, func() { _ = a.Close(); _ = b.Close() }
}

// pipeCipheredPacketStreams returns a pair of PacketStreamCiphers
// connected over net.Pipe + PacketStream + NovaWireStream. Handy for
// testing the whole stack.
func pipeCipheredPacketStreams(t *testing.T) (*novaproto.PacketStreamCipher, *novaproto.PacketStreamCipher, func()) {
	t.Helper()
	a, b := net.Pipe()
	client := novaproto.NewPacketStreamCipher(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(a)),
	)
	server := novaproto.NewPacketStreamCipher(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(b)),
	)
	return client, server, func() { _ = a.Close(); _ = b.Close() }
}

// --- PacketStream tests ----------------------------------------------

func TestPacketStreamRoundtrip(t *testing.T) {
	client, server, cleanup := pipePacketStreams(t)
	defer cleanup()

	payload := []byte("hello, one packet")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if _, err := w.Write(payload); err != nil {
			t.Errorf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, payload) {
		t.Errorf("payload: got %q, want %q", got, payload)
	}
}

func TestPacketStreamEmptyPacket(t *testing.T) {
	client, server, cleanup := pipePacketStreams(t)
	defer cleanup()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if len(got) != 0 {
		t.Errorf("expected empty packet, got %d bytes", len(got))
	}
}

// TestPacketStreamLargePacket sends a 4 MiB packet — deliberately much
// larger than one frame — and verifies byte-for-byte round-trip. This
// exercises streaming both in the writer (chunking into frames) and
// in the reader (io.Pipe back-pressure).
func TestPacketStreamLargePacket(t *testing.T) {
	client, server, cleanup := pipePacketStreams(t)
	defer cleanup()

	const size = 4 * 1024 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
			t.Errorf("Copy: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if len(got) != len(payload) {
		t.Fatalf("size: got %d, want %d", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Error("bytes differ after round-trip")
	}
}

// TestPacketStreamSequential sends N packets back-to-back and checks
// they arrive in order with the right content.
func TestPacketStreamSequential(t *testing.T) {
	client, server, cleanup := pipePacketStreams(t)
	defer cleanup()

	const n = 50
	payloads := make([][]byte, n)
	for i := 0; i < n; i++ {
		payloads[i] = []byte("packet-" + string(rune('A'+i%26)) + string(rune('0'+i%10)))
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			w := client.SendPacket()
			if _, err := w.Write(payloads[i]); err != nil {
				t.Errorf("[%d] Write: %v", i, err)
				return
			}
			if err := w.Close(); err != nil {
				t.Errorf("[%d] Close: %v", i, err)
				return
			}
		}
	}()

	for i := 0; i < n; i++ {
		r, err := server.ReceivePacket()
		if err != nil {
			t.Fatalf("[%d] ReceivePacket: %v", i, err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("[%d] ReadAll: %v", i, err)
		}
		if !bytes.Equal(got, payloads[i]) {
			t.Errorf("[%d] content: got %q, want %q", i, got, payloads[i])
		}
	}
	<-done
}

func TestPacketStreamEOF(t *testing.T) {
	a, b := net.Pipe()
	server := novaproto.NewPacketStream(novaproto.NewNovaWireStream(b))
	_ = a.Close()
	_, err := server.ReceivePacket()
	if err == nil {
		t.Fatal("expected error after peer close, got nil")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("expected EOF-ish error, got %v", err)
	}
	_ = b.Close()
}

// --- PacketStreamCipher tests ---------------------------------------

func TestPacketCipherPlainPassthrough(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	// No key installed → plain.
	if client.HasKey() || server.HasKey() {
		t.Fatal("HasKey should be false before SetKey")
	}

	payload := []byte("plain handshake bytes")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if _, err := w.Write(payload); err != nil {
			t.Errorf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, payload) {
		t.Errorf("payload: got %q, want %q", got, payload)
	}
}

func TestPacketCipherEncryptedRoundtrip(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	key := randKey(t)
	if err := client.SetKey(key); err != nil {
		t.Fatalf("client SetKey: %v", err)
	}
	if err := server.SetKey(key); err != nil {
		t.Fatalf("server SetKey: %v", err)
	}

	payload := []byte("this is confidential")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if _, err := w.Write(payload); err != nil {
			t.Errorf("Write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, payload) {
		t.Errorf("decrypted: got %q, want %q", got, payload)
	}
}

// TestPacketCipherLargeEncrypted sends a multi-chunk encrypted packet
// (> packetCipherChunkSize) and verifies byte-exact round-trip. This
// exercises the chunk-boundary logic and the final-chunk marker.
func TestPacketCipherLargeEncrypted(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	key := randKey(t)
	if err := client.SetKey(key); err != nil {
		t.Fatalf("client SetKey: %v", err)
	}
	if err := server.SetKey(key); err != nil {
		t.Fatalf("server SetKey: %v", err)
	}

	// Deliberately crosses several chunk boundaries and is not a
	// multiple of the chunk size, to exercise the partial final chunk.
	const size = 1024*1024*48 + 7
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
			t.Errorf("Copy: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, payload) {
		t.Errorf("large encrypted round-trip mismatch (%d bytes)", len(got))
	}
}

// TestPacketCipherLateKey walks the intended handshake flow: plain
// packet first, then SetKey on both sides, then encrypted packet on
// the same stream.
func TestPacketCipherLateKey(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	// Phase 1: plain handshake packet.
	handshake := []byte("ClientHello")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		_, _ = w.Write(handshake)
		_ = w.Close()
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("plain ReceivePacket: %v", err)
	}
	got, _ := io.ReadAll(r)
	wg.Wait()
	if !bytes.Equal(got, handshake) {
		t.Errorf("plain roundtrip: got %q, want %q", got, handshake)
	}

	// Phase 2: SetKey on both sides.
	key := randKey(t)
	if err := client.SetKey(key); err != nil {
		t.Fatalf("client SetKey: %v", err)
	}
	if err := server.SetKey(key); err != nil {
		t.Fatalf("server SetKey: %v", err)
	}

	// Phase 3: encrypted application packet.
	secret := []byte("now we are encrypted")
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		_, _ = w.Write(secret)
		_ = w.Close()
	}()

	r, err = server.ReceivePacket()
	if err != nil {
		t.Fatalf("encrypted ReceivePacket: %v", err)
	}
	got, err = io.ReadAll(r)
	if err != nil {
		t.Fatalf("encrypted ReadAll: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, secret) {
		t.Errorf("encrypted roundtrip: got %q, want %q", got, secret)
	}
}

// TestPacketCipherEncryptedWithoutKey verifies that receiving an
// encrypted packet without a key produces an error.
func TestPacketCipherEncryptedWithoutKey(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	// Only the sender has a key.
	if err := client.SetKey(randKey(t)); err != nil {
		t.Fatalf("client SetKey: %v", err)
	}

	go func() {
		w := client.SendPacket()
		_, _ = w.Write([]byte("boo"))
		_ = w.Close()
	}()

	r, err := server.ReceivePacket()
	if err == nil {
		// If the error surfaces on Read, not ReceivePacket, that's fine.
		_, err = io.ReadAll(r)
	}
	if err == nil {
		t.Error("expected error reading encrypted packet without key")
	}
}

// TestPacketCipherKeyMismatch installs different keys on both sides
// and expects AEAD Open to fail on receive.
func TestPacketCipherKeyMismatch(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	if err := client.SetKey(randKey(t)); err != nil {
		t.Fatalf("client SetKey: %v", err)
	}
	if err := server.SetKey(randKey(t)); err != nil {
		t.Fatalf("server SetKey: %v", err)
	}

	go func() {
		w := client.SendPacket()
		_, _ = w.Write([]byte("secret"))
		_ = w.Close()
	}()

	r, err := server.ReceivePacket()
	if err == nil {
		_, err = io.ReadAll(r)
	}
	if err == nil {
		t.Error("expected AEAD open failure with mismatched keys")
	}
}

// TestPacketCipherEmptyEncrypted seals a 0-byte packet — the writer
// must still emit the final marker chunk and the reader must return
// io.EOF promptly.
func TestPacketCipherEmptyEncrypted(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	key := randKey(t)
	if err := client.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if err := server.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := client.SendPacket()
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if len(got) != 0 {
		t.Errorf("expected 0 bytes, got %d", len(got))
	}
}

// TestPacketCipherStreamingSequential verifies back-to-back encrypted
// packets arrive correctly (no cross-packet state leakage, each packet
// gets its own base nonce).
func TestPacketCipherStreamingSequential(t *testing.T) {
	client, server, cleanup := pipeCipheredPacketStreams(t)
	defer cleanup()

	key := randKey(t)
	if err := client.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	if err := server.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	const n = 20
	payloads := make([][]byte, n)
	for i := 0; i < n; i++ {
		payloads[i] = bytes.Repeat([]byte{byte(i)}, 100+i*50)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			w := client.SendPacket()
			if _, err := w.Write(payloads[i]); err != nil {
				t.Errorf("[%d] Write: %v", i, err)
				return
			}
			if err := w.Close(); err != nil {
				t.Errorf("[%d] Close: %v", i, err)
				return
			}
		}
	}()

	for i := 0; i < n; i++ {
		r, err := server.ReceivePacket()
		if err != nil {
			t.Fatalf("[%d] ReceivePacket: %v", i, err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("[%d] ReadAll: %v", i, err)
		}
		if !bytes.Equal(got, payloads[i]) {
			t.Errorf("[%d] payload mismatch", i)
		}
	}
	<-done
}

// TestPacketCipherInterfaceSatisfaction is a compile-time sanity check
// that both concrete types satisfy PacketRW.
func TestPacketCipherInterfaceSatisfaction(t *testing.T) {
	var _ novaproto.PacketRW = (*novaproto.PacketStream)(nil)
	var _ novaproto.PacketRW = (*novaproto.PacketStreamCipher)(nil)
}
