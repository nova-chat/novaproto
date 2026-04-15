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

// Header is an alias for the unified framing header defined in
// internal/frame. It carries fragmentation info (FragmentNum /
// FragmentsCount / TotalSize) plus frame-level envelope fields that
// the codec fills in automatically on Encode.
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
//	[flag 1 | Header(HeaderSize) | metaLen 4 | payLen 4 | meta(metaLen) | payload(payLen)]
const plainPrefixLen = 1 + frame.HeaderSize + 4 + 4

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
	metaBytes, err := serializer.Marshal(&pkt.Meta)
	if err != nil {
		return nil, err
	}
	h := pkt.Header
	return c.frame.Seal(&h, metaBytes, pkt.Payload)
}

// Decode parses and decrypts a wire frame into a NovaServerPacket.
func (c *Codec) Decode(frameBytes []byte) (*NovaServerPacket, error) {
	header, metaBytes, payload, err := c.frame.Open(frameBytes)
	if err != nil {
		return nil, err
	}
	var meta Metadata
	if err := serializer.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	return &NovaServerPacket{
		Header:  *header,
		Meta:    meta,
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

	metaBytes, err := serializer.Marshal(&pkt.Meta)
	if err != nil {
		return nil, err
	}

	h := pkt.Header
	h.Magic = novaproto.Magic
	h.Version = novaproto.Version
	h.Length = uint32(len(metaBytes) + len(pkt.Payload))
	h.Nonce = [12]byte{}
	headerBuf, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	out := make([]byte, plainPrefixLen+len(metaBytes)+len(pkt.Payload))
	out[0] = byte(novaproto.FlagPlain)
	copy(out[1:], headerBuf)
	binary.BigEndian.PutUint32(out[1+frame.HeaderSize:], uint32(len(metaBytes)))
	binary.BigEndian.PutUint32(out[1+frame.HeaderSize+4:], uint32(len(pkt.Payload)))
	copy(out[plainPrefixLen:], metaBytes)
	copy(out[plainPrefixLen+len(metaBytes):], pkt.Payload)
	return out, nil
}

// DecodePlain reverses EncodePlain.
func DecodePlain(frameBytes []byte) (*NovaServerPacket, error) {
	if len(frameBytes) < plainPrefixLen {
		return nil, errors.New("c2s: plain frame too short")
	}
	if novaproto.Flag(frameBytes[0]) != novaproto.FlagPlain {
		return nil, errors.New("c2s: not a plain frame")
	}

	header, err := frame.UnmarshalHeader(frameBytes[1 : 1+frame.HeaderSize])
	if err != nil {
		return nil, err
	}
	if header.Magic != novaproto.Magic {
		return nil, errors.New("c2s: bad magic")
	}
	if header.Version != novaproto.Version {
		return nil, errors.New("c2s: unsupported plain version")
	}

	metaLen := binary.BigEndian.Uint32(frameBytes[1+frame.HeaderSize:])
	payLen := binary.BigEndian.Uint32(frameBytes[1+frame.HeaderSize+4:])
	if int(plainPrefixLen)+int(metaLen)+int(payLen) != len(frameBytes) {
		return nil, errors.New("c2s: plain length mismatch")
	}

	metaBytes := frameBytes[plainPrefixLen : plainPrefixLen+int(metaLen)]
	var meta Metadata
	if err := serializer.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	payload := append([]byte(nil), frameBytes[plainPrefixLen+int(metaLen):]...)
	return &NovaServerPacket{
		Header:  *header,
		Meta:    meta,
		Payload: payload,
	}, nil
}
