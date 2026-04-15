package novaproto_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto/c2c"
	"github.com/nova-chat/novaproto/c2s"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

// TestClientServerClientRelay demonstrates the full stacked flow:
//
//	client A                 server                    client B
//	--------                 ------                    --------
//	inner := c2c.Encode(pkt)
//	outer := c2s.Encode{..., Payload: inner}
//	                         sp := c2sA.Decode(outer)  // sees meta, not payload
//	                         out := c2sB.Encode{sp.Meta, sp.Payload}
//	                                                    sp := c2sB.Decode(out)
//	                                                    inner := sp.Payload
//	                                                    pkt := c2c.Decode(inner)
func TestClientServerClientRelay(t *testing.T) {
	// Link A↔S uses transportKeyA; link B↔S uses transportKeyB.
	// A and B share e2eKey; the server never sees it.
	transportKeyA := randKey(t)
	transportKeyB := randKey(t)
	e2eKey := randKey(t)

	// Client-side codecs
	c2cClient, err := c2c.NewCodec(e2eKey, nil)
	if err != nil {
		t.Fatalf("c2cClient: %v", err)
	}
	c2sClientA, err := c2s.NewCodec(transportKeyA, nil)
	if err != nil {
		t.Fatalf("c2sClientA: %v", err)
	}
	c2sClientB, err := c2s.NewCodec(transportKeyB, nil)
	if err != nil {
		t.Fatalf("c2sClientB: %v", err)
	}

	// Server-side codecs (one per client link)
	c2sServerA, err := c2s.NewCodec(transportKeyA, nil)
	if err != nil {
		t.Fatalf("c2sServerA: %v", err)
	}
	c2sServerB, err := c2s.NewCodec(transportKeyB, nil)
	if err != nil {
		t.Fatalf("c2sServerB: %v", err)
	}

	senderID := uuid.New()
	targetID := uuid.New()
	payload := []byte("end-to-end secret")

	// 1. Client A builds the c2c packet and encrypts it.
	innerPkt := &c2c.NovaPacket{
		Meta:    c2c.Metadata{ContentType: 42},
		Payload: payload,
	}
	innerFrame, err := c2cClient.Encode(innerPkt)
	if err != nil {
		t.Fatalf("c2c Encode: %v", err)
	}

	// 2. Client A wraps it inside a c2s packet addressed to B.
	outerPkt := &c2s.NovaServerPacket{
		Meta: c2s.Metadata{
			SenderID:    senderID,
			TargetID:    targetID,
			MessageType: 0,
		},
		Payload: innerFrame,
	}
	outerFrame, err := c2sClientA.Encode(outerPkt)
	if err != nil {
		t.Fatalf("c2s Encode: %v", err)
	}

	// 3. Server receives the outer frame on link A, decodes c2s layer.
	//    It sees the metadata but the payload stays opaque (still c2c-ciphertext).
	received, err := c2sServerA.Decode(outerFrame)
	if err != nil {
		t.Fatalf("server Decode: %v", err)
	}
	if received.Meta.SenderID != senderID || received.Meta.TargetID != targetID {
		t.Errorf("server meta mismatch: %+v", received.Meta)
	}
	if bytes.Contains(received.Payload, payload) {
		t.Error("server sees plaintext payload — e2e layer leaked")
	}

	// 4. Server re-wraps the opaque payload for client B's transport key.
	relayFrame, err := c2sServerB.Encode(&c2s.NovaServerPacket{
		Meta:    received.Meta,
		Payload: received.Payload,
	})
	if err != nil {
		t.Fatalf("server relay Encode: %v", err)
	}

	// 5. Client B decodes c2s layer, then c2c layer.
	recvOuter, err := c2sClientB.Decode(relayFrame)
	if err != nil {
		t.Fatalf("client B c2s Decode: %v", err)
	}
	if recvOuter.Meta.SenderID != senderID || recvOuter.Meta.TargetID != targetID {
		t.Errorf("client B meta mismatch: %+v", recvOuter.Meta)
	}

	recvInner, err := c2cClient.Decode(recvOuter.Payload)
	if err != nil {
		t.Fatalf("client B c2c Decode: %v", err)
	}
	if recvInner.Meta.ContentType != 42 {
		t.Errorf("ContentType: got %d, want 42", recvInner.Meta.ContentType)
	}
	if !bytes.Equal(recvInner.Payload, payload) {
		t.Errorf("Payload: got %q, want %q", recvInner.Payload, payload)
	}
}

// TestTCPRoundtrip30MB encodes a 30 MiB NovaPacket on one end of a localhost
// TCP connection and decodes it on the other, verifying bit-for-bit equality.
// Since the frame has its own length header, we just write the whole thing
// and let the receiver read until EOF (sender closes the write side).
func TestTCPRoundtrip30MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 30 MiB TCP roundtrip in short mode")
	}

	key := randKey(t)
	sender, err := c2c.NewCodec(key, nil)
	if err != nil {
		t.Fatalf("sender codec: %v", err)
	}
	receiver, err := c2c.NewCodec(key, nil)
	if err != nil {
		t.Fatalf("receiver codec: %v", err)
	}

	const payloadSize = 30 * 1024 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload gen: %v", err)
	}

	pkt := &c2c.NovaPacket{
		Meta:    c2c.Metadata{ContentType: 7},
		Payload: payload,
	}
	frame, err := sender.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		pkt *c2c.NovaPacket
		err error
	}
	resCh := make(chan result, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer conn.Close()

		data, err := io.ReadAll(conn)
		if err != nil {
			resCh <- result{err: err}
			return
		}
		p, err := receiver.Decode(data)
		resCh <- result{pkt: p, err: err}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write(frame); err != nil {
		conn.Close()
		t.Fatalf("write: %v", err)
	}
	// Signal EOF so the receiver's io.ReadAll returns.
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	defer conn.Close()

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("receive: %v", r.err)
		}
		if r.pkt.Meta.ContentType != pkt.Meta.ContentType {
			t.Errorf("ContentType: got %d, want %d", r.pkt.Meta.ContentType, pkt.Meta.ContentType)
		}
		if len(r.pkt.Payload) != len(payload) {
			t.Fatalf("payload length: got %d, want %d", len(r.pkt.Payload), len(payload))
		}
		if !bytes.Equal(r.pkt.Payload, payload) {
			t.Error("payload bytes differ after TCP roundtrip")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("timeout waiting for receive")
	}
}
