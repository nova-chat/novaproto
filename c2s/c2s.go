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
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/internal/frame"
	"github.com/nova-chat/novaproto/serializer"
)

// Header is an alias for the unified framing header defined in the
// top-level novaproto package. It carries fragmentation info
// (FragmentNum / FragmentsCount / TotalSize) plus frame-level envelope
// fields (IsEncrypted, Nonce, Magic, Version, Length) that the codec
// fills in automatically on Encode/EncodePlain.
type Header = novaproto.Header

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

// plainFrame is the wire-level struct for unencrypted c2s frames.
// Marshalled by the serializer package: 33-byte Header, followed by
// serializer's standard u32-length-prefixed byte slices for Meta and
// Payload.
type plainFrame struct {
	Header  novaproto.Header
	Meta    []byte
	Payload []byte
}

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
// Header.IsEncrypted field at offset 0. Works without a Codec instance,
// so it can be used during handshake before a transport key has been
// negotiated:
//
//	if c2s.IsPlain(frame) {
//	    pkt, err := c2s.DecodePlain(frame)
//	} else {
//	    pkt, err := codec.Decode(frame)
//	}
func IsPlain(frameBytes []byte) bool {
	return len(frameBytes) >= 1 && frameBytes[0] == 0
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
	h.IsEncrypted = false
	h.Magic = novaproto.Magic
	h.Version = novaproto.Version
	h.Length = uint32(len(metaBytes) + len(pkt.Payload))
	h.Nonce = [novaproto.NonceSize]byte{}

	return serializer.Marshal(&plainFrame{
		Header:  h,
		Meta:    metaBytes,
		Payload: pkt.Payload,
	})
}

// DecodePlain reverses EncodePlain.
func DecodePlain(frameBytes []byte) (*NovaServerPacket, error) {
	var pf plainFrame
	if err := serializer.Unmarshal(frameBytes, &pf); err != nil {
		return nil, err
	}
	if pf.Header.IsEncrypted {
		return nil, errors.New("c2s: not a plain frame")
	}
	if pf.Header.Magic != novaproto.Magic {
		return nil, errors.New("c2s: bad magic")
	}
	if pf.Header.Version != novaproto.Version {
		return nil, errors.New("c2s: unsupported plain version")
	}
	var meta Metadata
	if err := serializer.Unmarshal(pf.Meta, &meta); err != nil {
		return nil, err
	}
	return &NovaServerPacket{
		Header:  pf.Header,
		Meta:    meta,
		Payload: pf.Payload,
	}, nil
}
