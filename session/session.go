// Package session implements end-to-end encrypted conversations
// between two novaproto clients routed through a shared server.
//
// A Session represents a conversation with one peer, identified by a
// UUID, and combines three things into one outgoing-packet pipeline:
//
//  1. zlib streaming compression — applied on plaintext before
//     encryption so the cipher sees high-entropy compressed bytes and
//     the compressor benefits from plaintext redundancy.
//  2. chunked AES-GCM streaming encryption keyed with the shared
//     end-to-end key K_cc — per-chunk nonce and authentication,
//     truncation-safe (see chunkedaead.go).
//  3. packet framing via a novaproto.RoutedPacketStream with
//     PacketHeader.TargetID = peer and SourceID = self. The server
//     routes these packets opaquely; only the peer can decrypt.
//
// Send / Receive APIs come in two flavours:
//
//   - Bytes (small messages already in memory):
//     Send(kind, payload []byte) error
//     OpenBytes(incoming io.Reader) ([]byte, error)
//
//   - Streaming (large payloads or unknown length):
//     SendStream(kind) (io.WriteCloser, error)
//     OpenStream(incoming io.Reader) (io.Reader, error)
//
// On the receive side the caller is responsible for demultiplexing
// incoming routed packets by PacketHeader.SourceID and handing the
// pre-filtered packet reader to the right Session via OpenStream /
// OpenBytes. A typical loop on the receiving client looks like:
//
//	for {
//	    hdr, r, err := rps.ReceivePacket()
//	    if err != nil { ... }
//	    if hdr.TargetID == uuid.Nil {
//	        handleControl(hdr, r)
//	        continue
//	    }
//	    s := sessions[hdr.SourceID]
//	    if s == nil { io.Copy(io.Discard, r); continue }
//	    plain, err := s.OpenStream(r)
//	    if err != nil { ... }
//	    process(hdr.Kind, plain)
//	}
package session

import (
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto"
)

// Session is an e2e-encrypted conversation with one peer. It is not
// safe for concurrent Send calls — create one Session per sender
// goroutine if you need parallel sends to the same peer, or wrap
// calls with your own mutex.
type Session struct {
	rps    *novaproto.RoutedPacketStream
	selfID uuid.UUID
	peerID uuid.UUID
	aead   cipher.AEAD
}

// New constructs a Session for the conversation with peerID.
// key must be exactly 32 bytes (AES-256).
func New(rps *novaproto.RoutedPacketStream, selfID, peerID uuid.UUID, key []byte) (*Session, error) {
	if rps == nil {
		return nil, errors.New("session: nil RoutedPacketStream")
	}
	if len(key) != 32 {
		return nil, errors.New("session: key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("session: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("session: new GCM: %w", err)
	}
	return &Session{
		rps:    rps,
		selfID: selfID,
		peerID: peerID,
		aead:   aead,
	}, nil
}

// PeerID returns the UUID of the remote peer this Session talks to.
func (s *Session) PeerID() uuid.UUID { return s.peerID }

// SelfID returns the local client UUID advertised as SourceID in
// outgoing PacketHeaders.
func (s *Session) SelfID() uuid.UUID { return s.selfID }

// SendStream opens a new outgoing packet to the peer and returns an
// io.WriteCloser that accepts plaintext. Writes are streamed through
// zlib → chunked AEAD → the underlying RoutedPacketStream writer on
// the fly; nothing is buffered beyond the current zlib window and
// the current AEAD chunk.
//
// Close MUST be called. It flushes zlib, emits the final AEAD chunk
// and closes the inner packet (releases the send lock on the
// RoutedPacketStream). Forgetting Close deadlocks the next outgoing
// packet on that RoutedPacketStream.
func (s *Session) SendStream(kind uint64) (io.WriteCloser, error) {
	innerW, err := s.rps.SendPacket(novaproto.PacketHeader{
		TargetID: s.peerID,
		SourceID: s.selfID,
		Kind:     kind,
	})
	if err != nil {
		return nil, err
	}

	// Fresh base nonce per packet: 8 random bytes give 2^64 packets
	// before birthday collision under the same K_cc.
	var baseNonce [baseNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, baseNonce[:]); err != nil {
		_ = innerW.Close()
		return nil, fmt.Errorf("session: generate base nonce: %w", err)
	}
	if _, err := innerW.Write(baseNonce[:]); err != nil {
		_ = innerW.Close()
		return nil, fmt.Errorf("session: write base nonce: %w", err)
	}

	sealer := newSealingWriter(innerW, s.aead, baseNonce)
	zw := zlib.NewWriter(sealer)
	return &sessionWriter{zw: zw, sealer: sealer}, nil
}

// Send is a convenience wrapper over SendStream for small payloads
// already in memory. Internally it still streams; the difference is
// just ergonomic.
func (s *Session) Send(kind uint64, payload []byte) error {
	w, err := s.SendStream(kind)
	if err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

// OpenStream wraps a pre-filtered incoming packet reader with the
// symmetric decrypt + inflate pipeline. The returned reader yields
// plaintext until io.EOF at the packet boundary.
//
// The caller must first obtain `incoming` from
// RoutedPacketStream.ReceivePacket and verify that
// PacketHeader.SourceID == s.PeerID() and TargetID == s.SelfID();
// OpenStream does not re-check the routing.
func (s *Session) OpenStream(incoming io.Reader) (io.Reader, error) {
	var baseNonce [baseNonceSize]byte
	if _, err := io.ReadFull(incoming, baseNonce[:]); err != nil {
		return nil, fmt.Errorf("session: read base nonce: %w", err)
	}
	opener := newOpeningReader(incoming, s.aead, baseNonce)
	zr, err := zlib.NewReader(opener)
	if err != nil {
		return nil, fmt.Errorf("session: zlib reader: %w", err)
	}
	return &sessionReader{zr: zr}, nil
}

// OpenBytes is a convenience wrapper that reads the whole incoming
// packet to plaintext and returns it as a byte slice.
func (s *Session) OpenBytes(incoming io.Reader) ([]byte, error) {
	r, err := s.OpenStream(incoming)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// sessionWriter is the outgoing writer chain: app writes go into
// zlib, zlib flushes into the sealer, sealer seals chunks and writes
// them into the RoutedPacketStream's packet writer.
//
// Close order matters: zlib must flush its final blocks into the
// sealer before the sealer emits its final AEAD chunk, and the
// sealer's Close must close the inner packet writer last.
type sessionWriter struct {
	zw     *zlib.Writer
	sealer *sealingWriter
	closed bool
}

func (w *sessionWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("session: write on closed session writer")
	}
	return w.zw.Write(p)
}

func (w *sessionWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	// Flush zlib tail into the sealer first.
	if err := w.zw.Close(); err != nil {
		_ = w.sealer.Close()
		return fmt.Errorf("session: zlib close: %w", err)
	}
	// Then let the sealer emit its final chunk and close the inner
	// packet writer.
	return w.sealer.Close()
}

// sessionReader wires the incoming reader chain so that zlib.Reader
// pulls from the openingReader which pulls from the packet reader.
type sessionReader struct {
	zr io.ReadCloser
}

func (r *sessionReader) Read(p []byte) (int, error) {
	return r.zr.Read(p)
}
