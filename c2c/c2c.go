// Package c2c implements the client↔client end-to-end layer.
//
// NovaPacket is encrypted with an end-to-end key known only to the
// communicating clients. The resulting frame is then typically wrapped as
// the Payload of a c2s.NovaServerPacket so the server can route it without
// seeing the plaintext.
package c2c

import (
	"encoding/binary"
	"errors"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/internal/frame"
)

// NovaPacket is the user-facing end-to-end packet.
type NovaPacket struct {
	Meta    Metadata
	Payload []byte
}

// Metadata carries content metadata visible only to the peer client.
//
// Encrypted is an application-level flag telling the peer whether the
// Payload bytes carry another encrypted layer (e.g. re-wrapped blob,
// application-level sealed envelope) or are plaintext content. It is
// independent of the frame-level encryption already applied by Codec.Encode.
//
// FragmentNum / FragmentsCount let the sender split one logical message
// across multiple c2c frames so the receiver can reassemble them. For
// unfragmented messages set FragmentsCount = 1 and FragmentNum = 0.
type Metadata struct {
	ContentType    uint32
	Encrypted      bool
	FragmentNum    int16
	FragmentsCount int16
}

// Wire layout: [contentType u32 | encrypted u8 | fragmentNum i16 | fragmentsCount i16]
const metaSize = 4 + 1 + 2 + 2

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
	var metaBuf [metaSize]byte
	marshalMeta(&pkt.Meta, metaBuf[:])
	return c.frame.Seal(metaBuf[:], pkt.Payload)
}

// Decode parses and decrypts a wire frame into a NovaPacket.
func (c *Codec) Decode(frameBytes []byte) (*NovaPacket, error) {
	meta, payload, err := c.frame.Open(frameBytes)
	if err != nil {
		return nil, err
	}
	if len(meta) != metaSize {
		return nil, errors.New("c2c: meta size mismatch")
	}
	var m Metadata
	unmarshalMeta(meta, &m)
	return &NovaPacket{Meta: m, Payload: payload}, nil
}

func marshalMeta(m *Metadata, buf []byte) {
	binary.BigEndian.PutUint32(buf[0:], m.ContentType)
	if m.Encrypted {
		buf[4] = 1
	} else {
		buf[4] = 0
	}
	binary.BigEndian.PutUint16(buf[5:], uint16(m.FragmentNum))
	binary.BigEndian.PutUint16(buf[7:], uint16(m.FragmentsCount))
}

func unmarshalMeta(buf []byte, m *Metadata) {
	m.ContentType = binary.BigEndian.Uint32(buf[0:])
	m.Encrypted = buf[4] != 0
	m.FragmentNum = int16(binary.BigEndian.Uint16(buf[5:]))
	m.FragmentsCount = int16(binary.BigEndian.Uint16(buf[7:]))
}
