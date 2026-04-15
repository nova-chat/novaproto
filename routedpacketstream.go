package novaproto

import (
	"errors"
	"fmt"
	"io"

	"github.com/nova-chat/novaproto/serializer"
)

// RoutedPacketStream wraps a PacketRW and automatically handles the
// PacketHeader at the start of every packet body.
//
// Layering (typical client):
//
//	net.Conn
//	  ↓
//	NovaWireStream            (framing)
//	  ↓
//	NovaWireStreamCipher      (transport encryption, K_cs)
//	  ↓
//	PacketStream              (packet multiplexing)
//	  ↓
//	RoutedPacketStream        ← this type
//	  ↓
//	application
//
// On send, RoutedPacketStream serializes the caller's PacketHeader
// and writes it as the first bytes of the outgoing packet. Callers
// then stream the packet payload into the returned WriteCloser.
//
// On receive, it reads PacketHeaderSize bytes from the next incoming
// packet, unmarshals, verifies Magic, and returns the header plus an
// io.Reader for the remaining payload. The server dispatches on
// hdr.TargetID: uuid.Nil → the packet is for the server itself,
// otherwise it is forwarded opaquely to the target client.
//
// End-to-end encryption of the payload (for user-bound packets) is
// handled by the caller — e.g. by sealing with an AEAD keyed with
// K_cc before passing the bytes to the WriteCloser, and opening with
// the same key on the receiver. The packet layer never sees the
// e2e key.
type RoutedPacketStream struct {
	inner PacketRW
}

// NewRoutedPacketStream wraps an inner packet stream.
func NewRoutedPacketStream(inner PacketRW) *RoutedPacketStream {
	return &RoutedPacketStream{inner: inner}
}

// SendPacket begins a new outgoing packet with the given header.
// Magic is always overwritten with novaproto.Magic before
// serialization. Close must be called on the returned WriteCloser to
// finalize the packet.
func (r *RoutedPacketStream) SendPacket(hdr PacketHeader) (io.WriteCloser, error) {
	hdr.Magic = Magic
	hdrBytes, err := serializer.Marshal(&hdr)
	if err != nil {
		return nil, fmt.Errorf("routedpacketstream: marshal header: %w", err)
	}

	w := r.inner.SendPacket()
	if _, err := w.Write(hdrBytes); err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

// ReceivePacket blocks until the next incoming packet arrives, reads
// its PacketHeader, and returns (header, payload-reader, nil). The
// payload reader yields the bytes after the header until io.EOF at
// the packet boundary.
func (r *RoutedPacketStream) ReceivePacket() (PacketHeader, io.Reader, error) {
	inner, err := r.inner.ReceivePacket()
	if err != nil {
		return PacketHeader{}, nil, err
	}

	var buf [PacketHeaderSize]byte
	if _, err := io.ReadFull(inner, buf[:]); err != nil {
		return PacketHeader{}, nil, fmt.Errorf("routedpacketstream: read header: %w", err)
	}

	var hdr PacketHeader
	if err := serializer.Unmarshal(buf[:], &hdr); err != nil {
		return PacketHeader{}, nil, fmt.Errorf("routedpacketstream: unmarshal header: %w", err)
	}
	if hdr.Magic != Magic {
		return PacketHeader{}, nil, errors.New("routedpacketstream: bad packet header magic")
	}
	return hdr, inner, nil
}
