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

// NovaPacket is the user-facing end-to-end packet.
type NovaPacket struct {
	Header  Header
	Meta    Metadata
	Payload []byte
}

// Header carries c2c-level framing fields that live outside of Metadata.
//
// FragmentNum / FragmentsCount let the sender split one logical message
// across multiple c2c frames so the receiver can reassemble them. For
// unfragmented messages set FragmentsCount = 1 and FragmentNum = 0.
type Header struct {
	FragmentNum    int16
	FragmentsCount int16
}

// Metadata carries content metadata visible only to the peer client.
type Metadata struct {
	ContentType uint32
}

// inner is the wire-format struct carried inside the encrypted region.
// Header and Metadata are serialized together via the serializer package.
type inner struct {
	Header Header
	Meta   Metadata
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

func (c *Codec) GetMagic() uint32   { return novaproto.Magic }
func (c *Codec) GetVersion() uint32 { return novaproto.Version }

// Encode serializes and encrypts a NovaPacket into a wire frame.
func (c *Codec) Encode(pkt *NovaPacket) ([]byte, error) {
	if pkt == nil {
		return nil, errors.New("c2c: nil packet")
	}
	metaBytes, err := serializer.Marshal(&inner{Header: pkt.Header, Meta: pkt.Meta})
	if err != nil {
		return nil, err
	}
	return c.frame.Seal(metaBytes, pkt.Payload)
}

// Decode parses and decrypts a wire frame into a NovaPacket.
func (c *Codec) Decode(frameBytes []byte) (*NovaPacket, error) {
	metaBytes, payload, err := c.frame.Open(frameBytes)
	if err != nil {
		return nil, err
	}
	var in inner
	if err := serializer.Unmarshal(metaBytes, &in); err != nil {
		return nil, err
	}
	return &NovaPacket{
		Header:  in.Header,
		Meta:    in.Meta,
		Payload: payload,
	}, nil
}
