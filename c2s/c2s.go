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
	"github.com/nova-chat/novaproto/serializer"
)

// Header is an alias for the shared framing header defined in internal/frame.
// It carries fragmentation info (FragmentNum / FragmentsCount) — see
// frame.Header for full semantics.
type Header = frame.Header

// NovaServerPacket is the client↔server packet.
type NovaServerPacket struct {
	Header  Header
	Meta    Metadata
	Payload []byte
}

// Metadata is the c2s-layer routing metadata.
type Metadata struct {
	SenderID    uuid.UUID
	TargetID    uuid.UUID
	MessageType uint32
	Timestamp   int64
}

// Plain wire layout:
//
//	[flag 1 | magic 4 | version 4 | innerLen 4 | payLen 4 | inner(innerLen) | payload(payLen)]
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

// Encode serializes and encrypts a NovaServerPacket into a wire frame.
func (c *Codec) Encode(pkt *NovaServerPacket) ([]byte, error) {
	if pkt == nil {
		return nil, errors.New("c2s: nil packet")
	}
	if pkt.Meta.Timestamp == 0 {
		pkt.Meta.Timestamp = time.Now().UnixNano()
	}
	innerBytes, err := buildInner(&pkt.Header, &pkt.Meta)
	if err != nil {
		return nil, err
	}
	return c.frame.Seal(innerBytes, pkt.Payload)
}

// Decode parses and decrypts a wire frame into a NovaServerPacket.
func (c *Codec) Decode(frameBytes []byte) (*NovaServerPacket, error) {
	innerBytes, payload, err := c.frame.Open(frameBytes)
	if err != nil {
		return nil, err
	}
	header, meta, err := parseInner(innerBytes)
	if err != nil {
		return nil, err
	}
	return &NovaServerPacket{
		Header:  *header,
		Meta:    *meta,
		Payload: payload,
	}, nil
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

	innerBytes, err := buildInner(&pkt.Header, &pkt.Meta)
	if err != nil {
		return nil, err
	}

	out := make([]byte, plainHeaderLen+len(innerBytes)+len(pkt.Payload))
	out[0] = byte(novaproto.FlagPlain)
	binary.BigEndian.PutUint32(out[1:], novaproto.Magic)
	binary.BigEndian.PutUint32(out[5:], novaproto.Version)
	binary.BigEndian.PutUint32(out[9:], uint32(len(innerBytes)))
	binary.BigEndian.PutUint32(out[13:], uint32(len(pkt.Payload)))
	copy(out[plainHeaderLen:], innerBytes)
	copy(out[plainHeaderLen+len(innerBytes):], pkt.Payload)
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
	innerLen := binary.BigEndian.Uint32(frameBytes[9:])
	payLen := binary.BigEndian.Uint32(frameBytes[13:])
	if int(plainHeaderLen)+int(innerLen)+int(payLen) != len(frameBytes) {
		return nil, errors.New("c2s: plain length mismatch")
	}

	header, meta, err := parseInner(frameBytes[plainHeaderLen : plainHeaderLen+int(innerLen)])
	if err != nil {
		return nil, err
	}
	payload := append([]byte(nil), frameBytes[plainHeaderLen+int(innerLen):]...)
	return &NovaServerPacket{
		Header:  *header,
		Meta:    *meta,
		Payload: payload,
	}, nil
}

func buildInner(h *Header, m *Metadata) ([]byte, error) {
	headerBytes, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	metaBytes, err := serializer.Marshal(m)
	if err != nil {
		return nil, err
	}
	return append(headerBytes, metaBytes...), nil
}

func parseInner(buf []byte) (*Header, *Metadata, error) {
	header, metaBytes, err := frame.UnmarshalHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	var meta Metadata
	if err := serializer.Unmarshal(metaBytes, &meta); err != nil {
		return nil, nil, err
	}
	return header, &meta, nil
}
