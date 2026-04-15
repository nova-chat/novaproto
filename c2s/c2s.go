// Package c2s implements the client↔server transport layer.
//
// NovaServerPacket is encrypted with a transport key shared between one
// client and the server. Metadata (sender, target, type, timestamp) is
// readable by the server so it can route; Payload is opaque to the server
// and typically holds a c2c-encoded NovaPacket.
//
// The package also exposes EncodePlain/DecodePlain for unencrypted frames,
// used during the initial handshake before a transport key is established.
// Plain frames carry no confidentiality — they are intended for key
// exchange and version negotiation only.
package c2s

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/internal/frame"
)

// NovaServerPacket is the client↔server packet.
type NovaServerPacket struct {
	Meta    Metadata
	Payload []byte
}

// Metadata is the c2s-layer metadata. Fixed binary layout, 45 bytes:
//
//	sender(16) || target(16) || msgType(4) || timestamp(8) || encrypted(1)
//
// Encrypted is an application-level flag telling the receiver whether the
// Payload bytes carry another encrypted layer (typically a c2c frame) or
// plaintext server control data. It is independent of the frame-level
// encryption already applied by Codec.Encode / checked via IsPlain.
type Metadata struct {
	SenderID    uuid.UUID
	TargetID    uuid.UUID
	MessageType MessageType
	Timestamp   int64
	Encrypted   bool
}

type MessageType uint32

const (
	MsgUnknown MessageType = iota
	MsgHandshake
	MsgData
	MsgAck
	MsgControl
	MsgPing
	MsgPong
)

const metaSize = 16 + 16 + 4 + 8 + 1 // 45

// Plain wire layout:
//
//	[flag 1 | magic 4 | version 4 | metaLen 4 | payLen 4 | meta(metaLen) | payload(payLen)]
const plainHeaderLen = 1 + 4 + 4 + 4 + 4 // 17

// Codec encrypts and decrypts NovaServerPackets with the transport key.
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

// Encode serializes and encrypts a NovaServerPacket into a wire frame.
func (c *Codec) Encode(pkt *NovaServerPacket) ([]byte, error) {
	if pkt == nil {
		return nil, errors.New("c2s: nil packet")
	}
	if pkt.Meta.Timestamp == 0 {
		pkt.Meta.Timestamp = time.Now().UnixNano()
	}
	var metaBuf [metaSize]byte
	marshalMeta(&pkt.Meta, metaBuf[:])
	return c.frame.Seal(metaBuf[:], pkt.Payload)
}

// Decode parses and decrypts a wire frame into a NovaServerPacket.
func (c *Codec) Decode(frameBytes []byte) (*NovaServerPacket, error) {
	meta, payload, err := c.frame.Open(frameBytes)
	if err != nil {
		return nil, err
	}
	if len(meta) != metaSize {
		return nil, errors.New("c2s: meta size mismatch")
	}
	var m Metadata
	unmarshalMeta(meta, &m)
	return &NovaServerPacket{Meta: m, Payload: payload}, nil
}

// IsPlain reports whether a frame is a plaintext c2s frame, based on the
// one-byte flag at offset 0. Works without a Codec instance, so it can be
// used during handshake before a transport key has been negotiated:
//
//	if c2s.IsPlain(frame) {
//	    pkt, err := c2s.DecodePlain(frame)
//	} else {
//	    pkt, err := codec.Decode(frame)
//	}
func IsPlain(frameBytes []byte) bool {
	return len(frameBytes) >= 1 && novaproto.Flag(frameBytes[0]) == novaproto.FlagPlain
}

// EncodePlain serializes a NovaServerPacket without encryption. Intended for
// handshake frames sent before a transport key has been negotiated. The
// payload is sent in the clear — do not put sensitive data here.
func EncodePlain(pkt *NovaServerPacket) ([]byte, error) {
	if pkt == nil {
		return nil, errors.New("c2s: nil packet")
	}
	if pkt.Meta.Timestamp == 0 {
		pkt.Meta.Timestamp = time.Now().UnixNano()
	}

	var metaBuf [metaSize]byte
	marshalMeta(&pkt.Meta, metaBuf[:])

	out := make([]byte, plainHeaderLen+metaSize+len(pkt.Payload))
	out[0] = byte(novaproto.FlagPlain)
	binary.BigEndian.PutUint32(out[1:], novaproto.Magic)
	binary.BigEndian.PutUint32(out[5:], novaproto.Version)
	binary.BigEndian.PutUint32(out[9:], uint32(metaSize))
	binary.BigEndian.PutUint32(out[13:], uint32(len(pkt.Payload)))
	copy(out[plainHeaderLen:], metaBuf[:])
	copy(out[plainHeaderLen+metaSize:], pkt.Payload)
	return out, nil
}

// DecodePlain reverses EncodePlain.
func DecodePlain(frameBytes []byte) (*NovaServerPacket, error) {
	if len(frameBytes) < plainHeaderLen {
		return nil, errors.New("c2s: plain frame too short")
	}
	if novaproto.Flag(frameBytes[0]) != novaproto.FlagPlain {
		return nil, errors.New("c2s: not a plain frame")
	}
	magic := binary.BigEndian.Uint32(frameBytes[1:])
	if magic != novaproto.Magic {
		return nil, errors.New("c2s: bad magic")
	}
	version := binary.BigEndian.Uint32(frameBytes[5:])
	if version != novaproto.Version {
		return nil, errors.New("c2s: unsupported plain version")
	}
	metaLen := binary.BigEndian.Uint32(frameBytes[9:])
	payLen := binary.BigEndian.Uint32(frameBytes[13:])
	if metaLen != metaSize {
		return nil, errors.New("c2s: plain meta size mismatch")
	}
	if int(plainHeaderLen+metaLen+payLen) != len(frameBytes) {
		return nil, errors.New("c2s: plain length mismatch")
	}

	var m Metadata
	unmarshalMeta(frameBytes[plainHeaderLen:plainHeaderLen+metaLen], &m)
	payload := append([]byte(nil), frameBytes[plainHeaderLen+metaLen:]...)
	return &NovaServerPacket{Meta: m, Payload: payload}, nil
}

func marshalMeta(m *Metadata, buf []byte) {
	off := 0
	copy(buf[off:off+16], m.SenderID[:])
	off += 16
	copy(buf[off:off+16], m.TargetID[:])
	off += 16
	binary.BigEndian.PutUint32(buf[off:], uint32(m.MessageType))
	off += 4
	binary.BigEndian.PutUint64(buf[off:], uint64(m.Timestamp))
	off += 8
	if m.Encrypted {
		buf[off] = 1
	} else {
		buf[off] = 0
	}
}

func unmarshalMeta(buf []byte, m *Metadata) {
	off := 0
	copy(m.SenderID[:], buf[off:off+16])
	off += 16
	copy(m.TargetID[:], buf[off:off+16])
	off += 16
	m.MessageType = MessageType(binary.BigEndian.Uint32(buf[off:]))
	off += 4
	m.Timestamp = int64(binary.BigEndian.Uint64(buf[off:]))
	off += 8
	m.Encrypted = buf[off] != 0
}
