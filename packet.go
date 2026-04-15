package novaproto

import "io"

// PacketRW is the minimal packet-level interface. PacketStream and
// any future packet-level wrapper satisfy it, so higher layers can be
// written against PacketRW without depending on a concrete type.
//
// SendPacket returns a WriteCloser streaming one outgoing packet;
// Close must be called to finish the packet. ReceivePacket blocks
// until the next incoming packet starts and returns an io.Reader
// that yields its content until io.EOF.
type PacketRW interface {
	SendPacket() io.WriteCloser
	ReceivePacket() (io.Reader, error)
}

// Compile-time assertion that the concrete type satisfies PacketRW.
var _ PacketRW = (*PacketStream)(nil)
