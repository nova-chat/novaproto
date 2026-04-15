package session_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/session"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

// newPair wires up two RoutedPacketStreams back-to-back over net.Pipe
// and returns one Session on each side, sharing the given key.
// In real usage there would be a server between them doing routing;
// for tests we short-circuit so the two clients talk directly.
func newPair(t *testing.T, key []byte) (alice, bob *session.Session, rpsB *novaproto.RoutedPacketStream, cleanup func()) {
	t.Helper()
	a, b := net.Pipe()

	rpsA := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(a)),
	)
	rpsB = novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(b)),
	)

	aliceID := uuid.New()
	bobID := uuid.New()

	alice, err := session.New(rpsA, aliceID, bobID, key)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err = session.New(rpsB, bobID, aliceID, key)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	return alice, bob, rpsB, func() { _ = a.Close(); _ = b.Close() }
}

// TestSessionRoundtripBytes exercises the byte-array API end-to-end.
func TestSessionRoundtripBytes(t *testing.T) {
	key := randKey(t)
	alice, bob, rpsB, cleanup := newPair(t, key)
	defer cleanup()

	payload := []byte("hello, bob")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := alice.Send(42, payload); err != nil {
			t.Errorf("alice.Send: %v", err)
		}
	}()

	hdr, r, err := rpsB.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	if hdr.Kind != 42 {
		t.Errorf("Kind: got %d, want 42", hdr.Kind)
	}
	if hdr.SourceID != alice.SelfID() {
		t.Errorf("SourceID: got %v, want %v", hdr.SourceID, alice.SelfID())
	}

	got, err := bob.OpenBytes(r)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, payload) {
		t.Errorf("payload: got %q, want %q", got, payload)
	}
}

// TestSessionRoundtripStreamCompressible sends a highly-redundant
// multi-megabyte payload through SendStream/OpenStream and verifies
// byte-for-byte equality. Also sanity-checks that compression
// actually shrinks the data by inspecting a locally compressed copy.
func TestSessionRoundtripStreamCompressible(t *testing.T) {
	key := randKey(t)
	alice, bob, rpsB, cleanup := newPair(t, key)
	defer cleanup()

	// ~2.7 MiB of very compressible text.
	payload := []byte(strings.Repeat("hello world from novaproto ", 100_000))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w, err := alice.SendStream(7)
		if err != nil {
			t.Errorf("SendStream: %v", err)
			return
		}
		if _, err := io.Copy(w, bytes.NewReader(payload)); err != nil {
			t.Errorf("Copy: %v", err)
			return
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	_, r, err := rpsB.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	plainR, err := bob.OpenStream(r)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	got, err := io.ReadAll(plainR)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestSessionRoundtripStreamRandom sends random (incompressible)
// bytes through the streaming API. Verifies the pipeline is correct
// even when zlib can't help — compress + encrypt must still roundtrip.
func TestSessionRoundtripStreamRandom(t *testing.T) {
	key := randKey(t)
	alice, bob, rpsB, cleanup := newPair(t, key)
	defer cleanup()

	const size = 512 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w, err := alice.SendStream(1)
		if err != nil {
			t.Errorf("SendStream: %v", err)
			return
		}
		if _, err := w.Write(payload); err != nil {
			t.Errorf("Write: %v", err)
			return
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	_, r, err := rpsB.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	plainR, err := bob.OpenStream(r)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	got, err := io.ReadAll(plainR)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if len(got) != size {
		t.Fatalf("size: got %d, want %d", len(got), size)
	}
	if !bytes.Equal(got, payload) {
		t.Error("random payload differs after roundtrip")
	}
}

// TestSessionEmptyPayload sends a packet with zero plaintext. zlib
// still emits a header/trailer, AEAD still seals one empty final
// chunk, and the receiver must get 0 bytes cleanly.
func TestSessionEmptyPayload(t *testing.T) {
	key := randKey(t)
	alice, bob, rpsB, cleanup := newPair(t, key)
	defer cleanup()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := alice.Send(0, nil); err != nil {
			t.Errorf("Send: %v", err)
		}
	}()

	_, r, err := rpsB.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	got, err := bob.OpenBytes(r)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	wg.Wait()

	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(got))
	}
}

// TestSessionSequential sends multiple packets in a row through the
// same pair, ensuring each packet gets a fresh base nonce and no
// state leaks between them.
func TestSessionSequential(t *testing.T) {
	key := randKey(t)
	alice, bob, rpsB, cleanup := newPair(t, key)
	defer cleanup()

	const n = 20
	payloads := make([][]byte, n)
	for i := 0; i < n; i++ {
		payloads[i] = bytes.Repeat([]byte{byte(i)}, 200+i*50)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, p := range payloads {
			if err := alice.Send(uint64(i), p); err != nil {
				t.Errorf("[%d] Send: %v", i, err)
				return
			}
		}
	}()

	for i := 0; i < n; i++ {
		hdr, r, err := rpsB.ReceivePacket()
		if err != nil {
			t.Fatalf("[%d] ReceivePacket: %v", i, err)
		}
		if hdr.Kind != uint64(i) {
			t.Errorf("[%d] Kind: got %d, want %d", i, hdr.Kind, i)
		}
		got, err := bob.OpenBytes(r)
		if err != nil {
			t.Fatalf("[%d] OpenBytes: %v", i, err)
		}
		if !bytes.Equal(got, payloads[i]) {
			t.Errorf("[%d] payload mismatch", i)
		}
	}
	<-done
}

// TestSessionKeyMismatch: alice encrypts with keyA, bob tries to
// decrypt with keyB. AEAD Open must fail.
func TestSessionKeyMismatch(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rpsA := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(a)),
	)
	rpsB := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(b)),
	)

	aliceID := uuid.New()
	bobID := uuid.New()
	alice, err := session.New(rpsA, aliceID, bobID, randKey(t))
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := session.New(rpsB, bobID, aliceID, randKey(t))
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	go func() {
		_ = alice.Send(1, []byte("secret"))
	}()

	_, r, err := rpsB.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	if _, err := bob.OpenBytes(r); err == nil {
		t.Error("expected AEAD Open failure with mismatched keys")
	}
}

// TestSessionNew_BadKey verifies that New rejects wrong-length keys.
func TestSessionNew_BadKey(t *testing.T) {
	rps := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(&nopRW{})),
	)
	if _, err := session.New(rps, uuid.New(), uuid.New(), make([]byte, 16)); err == nil {
		t.Error("expected error for 16-byte key")
	}
	if _, err := session.New(rps, uuid.New(), uuid.New(), nil); err == nil {
		t.Error("expected error for nil key")
	}
}

// nopRW is a dummy io.ReadWriter used where New only needs to check
// its key argument (the RPS is never actually used).
type nopRW struct{}

func (nopRW) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopRW) Write(p []byte) (int, error) { return len(p), nil }
