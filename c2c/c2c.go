// Package c2c implements the client↔client end-to-end layer.
//
// NovaPacket is encrypted with an end-to-end key known only to the
// communicating clients. The resulting frame is then typically wrapped as
// the Payload of a c2s.NovaServerPacket so the server can route it without
// seeing the plaintext.
package c2c

import (
	"errors"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/internal/frame"
	"github.com/nova-chat/novaproto/serializer"
)

// Header is an alias for the shared framing header defined in internal/frame.
// It carries fragmentation info (FragmentNum / FragmentsCount) — see
// frame.Header for full semantics.
type Header = frame.Header

// NovaPacket is the user-facing end-to-end packet.
type NovaPacket struct {
	Header  Header
	Meta    Metadata
	Payload []byte
}

// Metadata carries content metadata visible only to the peer client.
type Metadata struct {
	ContentType uint32
}

// Codec encrypts and decrypts NovaPackets with the end-to-end key.
type Codec struct {
	frame *frame.Codec
}

func NewCodec(key []byte, opts *novaproto.Options) (*Codec, error) {
	f, err := frame.NewCodec(key, opts)
	if err != nil {
		return nil, err
	}
	return &Codec{frame: f}, nil
}

// Encode serializes and encrypts a NovaPacket into a wire frame.
func (c *Codec) Encode(pkt *NovaPacket) ([]byte, error) {
	if pkt == nil {
		return nil, errors.New("c2c: nil packet")
	}
	headerBytes, err := pkt.Header.Marshal()
	if err != nil {
		return nil, err
	}
	metaBytes, err := serializer.Marshal(&pkt.Meta)
	if err != nil {
		return nil, err
	}
	return c.frame.Seal(append(headerBytes, metaBytes...), pkt.Payload)
}

// Decode parses and decrypts a wire frame into a NovaPacket.
func (c *Codec) Decode(frameBytes []byte) (*NovaPacket, error) {
	innerBytes, payload, err := c.frame.Open(frameBytes)
	if err != nil {
		return nil, err
	}
	header, metaBytes, err := frame.UnmarshalHeader(innerBytes)
	if err != nil {
		return nil, err
	}
	var meta Metadata
	if err := serializer.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	return &NovaPacket{
		Header:  *header,
		Meta:    meta,
		Payload: payload,
	}, nil
}
