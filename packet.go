package novaproto

import "io"

// PacketRW is the minimal packet-level interface. Both PacketStream
// (raw packet multiplexing over a Wire) and PacketStreamCipher
// (the same with optional per-packet AEAD) satisfy it, so higher
// layers can be written against PacketRW and run over a plaintext or
// encrypted transport interchangeably — exactly like Wire does one
// level down.
//
// SendPacket returns a WriteCloser streaming one outgoing packet;
// Close must be called to finish the packet. ReceivePacket blocks
// until the next incoming packet starts and returns an io.Reader
// that yields its content until io.EOF.
type PacketRW interface {
	SendPacket() io.WriteCloser
	ReceivePacket() (io.Reader, error)
}

// Compile-time assertions that the concrete types satisfy PacketRW.
var (
	_ PacketRW = (*PacketStream)(nil)
	_ PacketRW = (*PacketStreamCipher)(nil)
)
