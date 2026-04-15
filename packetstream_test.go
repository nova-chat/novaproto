package novaproto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
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

// TestPacketStreamConcurrentSends fires N goroutines each opening
// their own packet via SendPacket and writing a unique payload. The
// receiver picks up all N readers, drains them in parallel goroutines
// (per-packet drain is required to avoid head-of-line blocking under
// multiplexed sends), and verifies every payload arrived intact.
func TestPacketStreamConcurrentSends(t *testing.T) {
	client, server, cleanup := pipePacketStreams(t)
	defer cleanup()

	const N = 50

	var sendWg sync.WaitGroup
	for i := 0; i < N; i++ {
		sendWg.Add(1)
		go func(i int) {
			defer sendWg.Done()
			w := client.SendPacket()
			payload := []byte(fmt.Sprintf("packet-%04d", i))
			if _, err := w.Write(payload); err != nil {
				t.Errorf("[%d] Write: %v", i, err)
				return
			}
			if err := w.Close(); err != nil {
				t.Errorf("[%d] Close: %v", i, err)
			}
		}(i)
	}

	received := make(chan string, N)
	var recvWg sync.WaitGroup
	for i := 0; i < N; i++ {
		r, err := server.ReceivePacket()
		if err != nil {
			t.Fatalf("ReceivePacket: %v", err)
		}
		recvWg.Add(1)
		go func(r io.Reader) {
			defer recvWg.Done()
			got, err := io.ReadAll(r)
			if err != nil {
				t.Errorf("ReadAll: %v", err)
				return
			}
			received <- string(got)
		}(r)
	}
	sendWg.Wait()
	recvWg.Wait()
	close(received)

	seen := make(map[string]bool, N)
	for s := range received {
		seen[s] = true
	}
	if len(seen) != N {
		t.Errorf("got %d distinct packets, want %d", len(seen), N)
	}
	for i := 0; i < N; i++ {
		want := fmt.Sprintf("packet-%04d", i)
		if !seen[want] {
			t.Errorf("missing %q", want)
		}
	}
}

// TestPacketStreamConcurrentLargeAndSmall sends one big multi-frame
// packet and several small single-frame packets concurrently from
// independent goroutines. Verifies that small packets aren't blocked
// behind the big one — frames of different packets interleave on the
// wire and demultiplex correctly on the receive side.
func TestPacketStreamConcurrentLargeAndSmall(t *testing.T) {
	client, server, cleanup := pipePacketStreams(t)
	defer cleanup()

	const largeSize = 4 * 1024 * 1024
	largePayload := make([]byte, largeSize)
	if _, err := rand.Read(largePayload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	smalls := []string{"alpha", "beta", "gamma", "delta", "epsilon"}

	var sendWg sync.WaitGroup
	sendWg.Add(2)
	go func() {
		defer sendWg.Done()
		w := client.SendPacket()
		if _, err := io.Copy(w, bytes.NewReader(largePayload)); err != nil {
			t.Errorf("large copy: %v", err)
			return
		}
		if err := w.Close(); err != nil {
			t.Errorf("large close: %v", err)
		}
	}()
	go func() {
		defer sendWg.Done()
		for _, s := range smalls {
			w := client.SendPacket()
			if _, err := w.Write([]byte(s)); err != nil {
				t.Errorf("small write: %v", err)
				return
			}
			if err := w.Close(); err != nil {
				t.Errorf("small close: %v", err)
				return
			}
		}
	}()

	type result struct {
		payload []byte
		large   bool
	}
	total := 1 + len(smalls)
	resCh := make(chan result, total)

	var recvWg sync.WaitGroup
	for i := 0; i < total; i++ {
		r, err := server.ReceivePacket()
		if err != nil {
			t.Fatalf("ReceivePacket: %v", err)
		}
		recvWg.Add(1)
		go func(r io.Reader) {
			defer recvWg.Done()
			got, err := io.ReadAll(r)
			if err != nil {
				t.Errorf("drain: %v", err)
				return
			}
			resCh <- result{payload: got, large: len(got) == largeSize}
		}(r)
	}

	sendWg.Wait()
	recvWg.Wait()
	close(resCh)

	var gotLarge bool
	seenSmalls := make(map[string]bool)
	for r := range resCh {
		if r.large {
			if !bytes.Equal(r.payload, largePayload) {
				t.Error("large payload mismatch")
			}
			gotLarge = true
		} else {
			seenSmalls[string(r.payload)] = true
		}
	}
	if !gotLarge {
		t.Error("missing large packet")
	}
	for _, s := range smalls {
		if !seenSmalls[s] {
			t.Errorf("missing small %q", s)
		}
	}
}
