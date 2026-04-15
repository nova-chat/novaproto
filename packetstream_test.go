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
