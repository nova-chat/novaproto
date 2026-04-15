package novaproto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/serializer"
)

func pipeRouted(t *testing.T) (*novaproto.RoutedPacketStream, *novaproto.RoutedPacketStream, func()) {
	t.Helper()
	a, b := net.Pipe()
	client := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(a)),
	)
	server := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(b)),
	)
	return client, server, func() { _ = a.Close(); _ = b.Close() }
}

// TestPacketHeaderSizeMatchesSerialized guards against PacketHeaderSize
// drifting out of sync with the struct's actual serializer output.
func TestPacketHeaderSizeMatchesSerialized(t *testing.T) {
	h := novaproto.PacketHeader{
		Magic:    novaproto.Magic,
		TargetID: uuid.New(),
		SourceID: uuid.New(),
		Kind:     42,
	}
	buf, err := serializer.Marshal(&h)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(buf) != novaproto.PacketHeaderSize {
		t.Errorf("serialized size: got %d, want %d", len(buf), novaproto.PacketHeaderSize)
	}
}

// TestRoutedPacketStreamServerBound sends a packet with TargetID=Nil
// and verifies the server-side dispatch reads the header and the
// payload.
func TestRoutedPacketStreamServerBound(t *testing.T) {
	client, server, cleanup := pipeRouted(t)
	defer cleanup()

	sourceID := uuid.New()
	payload := []byte("control message for server")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w, err := client.SendPacket(novaproto.PacketHeader{
			TargetID: uuid.Nil,
			SourceID: sourceID,
			Kind:     42,
		})
		if err != nil {
			t.Errorf("SendPacket: %v", err)
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

	hdr, r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}

	if hdr.Magic != novaproto.Magic {
		t.Errorf("Magic: got %#x, want %#x", hdr.Magic, novaproto.Magic)
	}
	if hdr.TargetID != uuid.Nil {
		t.Errorf("TargetID: got %v, want Nil", hdr.TargetID)
	}
	if hdr.SourceID != sourceID {
		t.Errorf("SourceID: got %v, want %v", hdr.SourceID, sourceID)
	}
	if hdr.Kind != 42 {
		t.Errorf("Kind: got %d, want 42", hdr.Kind)
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

// TestRoutedPacketStreamUserRelay sends a packet with a non-nil
// TargetID and verifies the header preserves all routing fields.
func TestRoutedPacketStreamUserRelay(t *testing.T) {
	client, server, cleanup := pipeRouted(t)
	defer cleanup()

	sourceID := uuid.New()
	targetID := uuid.New()
	opaqueBlob := []byte("[pretend this is an e2e-sealed ciphertext]")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w, err := client.SendPacket(novaproto.PacketHeader{
			TargetID: targetID,
			SourceID: sourceID,
			Kind:     7,
		})
		if err != nil {
			t.Errorf("SendPacket: %v", err)
			return
		}
		_, _ = w.Write(opaqueBlob)
		_ = w.Close()
	}()

	hdr, r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}

	if hdr.TargetID != targetID {
		t.Errorf("TargetID: got %v, want %v", hdr.TargetID, targetID)
	}
	if hdr.SourceID != sourceID {
		t.Errorf("SourceID: got %v, want %v", hdr.SourceID, sourceID)
	}
	if hdr.Kind != 7 {
		t.Errorf("Kind: got %d, want 7", hdr.Kind)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if !bytes.Equal(got, opaqueBlob) {
		t.Errorf("payload: got %q, want %q", got, opaqueBlob)
	}
}

// TestRoutedPacketStreamEmptyPayload sends a packet with only a header
// and no payload; Close without Write must still be handled.
func TestRoutedPacketStreamEmptyPayload(t *testing.T) {
	client, server, cleanup := pipeRouted(t)
	defer cleanup()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w, err := client.SendPacket(novaproto.PacketHeader{Kind: 1})
		if err != nil {
			t.Errorf("SendPacket: %v", err)
			return
		}
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	hdr, r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	if hdr.Kind != 1 {
		t.Errorf("Kind: got %d, want 1", hdr.Kind)
	}
	got, _ := io.ReadAll(r)
	wg.Wait()

	if len(got) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(got))
	}
}

// TestRoutedPacketStreamSequential sends multiple packets back-to-back
// and verifies they arrive in order with correct headers.
func TestRoutedPacketStreamSequential(t *testing.T) {
	client, server, cleanup := pipeRouted(t)
	defer cleanup()

	const n = 20
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := uint64(0); i < n; i++ {
			w, err := client.SendPacket(novaproto.PacketHeader{Kind: i})
			if err != nil {
				t.Errorf("[%d] SendPacket: %v", i, err)
				return
			}
			_, _ = w.Write([]byte{byte(i)})
			_ = w.Close()
		}
	}()

	for i := uint64(0); i < n; i++ {
		hdr, r, err := server.ReceivePacket()
		if err != nil {
			t.Fatalf("[%d] ReceivePacket: %v", i, err)
		}
		if hdr.Kind != i {
			t.Errorf("[%d] Kind: got %d, want %d", i, hdr.Kind, i)
		}
		got, _ := io.ReadAll(r)
		if len(got) != 1 || got[0] != byte(i) {
			t.Errorf("[%d] payload: got %v, want [%d]", i, got, i)
		}
	}
	<-done
}

// TestRoutedPacketStreamLargeStreamingPayload ensures that a packet
// substantially larger than one frame is streamed through end-to-end
// without buffering, with the header read first so the server could
// in principle start routing before the full packet arrives.
func TestRoutedPacketStreamLargeStreamingPayload(t *testing.T) {
	client, server, cleanup := pipeRouted(t)
	defer cleanup()

	const size = 4 * 1024 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	sourceID := uuid.New()
	targetID := uuid.New()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w, err := client.SendPacket(novaproto.PacketHeader{
			TargetID: targetID,
			SourceID: sourceID,
			Kind:     99,
		})
		if err != nil {
			t.Errorf("SendPacket: %v", err)
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

	hdr, r, err := server.ReceivePacket()
	if err != nil {
		t.Fatalf("ReceivePacket: %v", err)
	}
	if hdr.TargetID != targetID || hdr.SourceID != sourceID || hdr.Kind != 99 {
		t.Errorf("header mismatch: %+v", hdr)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wg.Wait()

	if len(got) != size {
		t.Fatalf("size: got %d, want %d", len(got), size)
	}
	if !bytes.Equal(got, payload) {
		t.Error("bytes differ after round-trip")
	}
}

// TestRoutedPacketStreamBadMagicRejected constructs a wire buffer by
// hand with a tampered PacketHeader.Magic and verifies ReceivePacket
// rejects it.
func TestRoutedPacketStreamBadMagicRejected(t *testing.T) {
	// Build a packet body with a deliberately wrong magic, then frame
	// it manually so we control the exact bytes on the wire.
	bad := novaproto.PacketHeader{
		Magic:    0xDEADBEEF, // intentionally wrong
		TargetID: uuid.New(),
		SourceID: uuid.New(),
		Kind:     1,
	}
	badBody, err := serializer.Marshal(&bad)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// One data frame carrying the bad header, then a terminating frame.
	dataHdr := novaproto.FrameHeader{
		Magic:       novaproto.Magic,
		ContentSize: uint32(len(badBody)),
		FrameNonce:  1,
		PacketNonce: 1,
	}
	dataHdrBytes, err := serializer.Marshal(&dataHdr)
	if err != nil {
		t.Fatalf("Marshal frame header: %v", err)
	}

	termHdr := novaproto.FrameHeader{
		Magic:         novaproto.Magic,
		ContentSize:   0,
		FrameNonce:    2,
		PacketNonce:   1,
		IsTerminating: true,
	}
	termHdrBytes, err := serializer.Marshal(&termHdr)
	if err != nil {
		t.Fatalf("Marshal term header: %v", err)
	}

	var buf bytes.Buffer
	buf.Write(dataHdrBytes)
	buf.Write(badBody)
	buf.Write(termHdrBytes)

	server := novaproto.NewRoutedPacketStream(
		novaproto.NewPacketStream(novaproto.NewNovaWireStream(&buf)),
	)
	_, _, err = server.ReceivePacket()
	if err == nil {
		t.Fatal("expected bad magic rejection")
	}
}
