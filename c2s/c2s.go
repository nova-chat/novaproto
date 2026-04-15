// Package c2s implements the client↔server transport layer.
//
// NovaServerPacket is encrypted with a transport key shared between one
// client and the server. Metadata (sender, target, type, timestamp) is
// readable by the server so it can route; Payload is opaque to the server
// and typically holds a c2c-encoded NovaPacket.
//
// Encode dispatches on HeaderParams.IsEncrypted: true produces a sealed
// frame, false produces a plain handshake frame (no confidentiality,
// used for key exchange and version negotiation only).
package c2s

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/internal/frame"
	"github.com/nova-chat/novaproto/serializer"
)

// NovaServerPacket is the client↔server packet. Framing metadata
// (nonce, fragmentation, encryption flag) is passed separately as
// novaproto.HeaderParams to Encode / returned from Decode.
type NovaServerPacket struct {
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

// Encode serializes a NovaServerPacket into a wire frame. If
// params.IsEncrypted is true the frame is sealed with the codec's
// transport key; otherwise it is emitted in the clear as a plain
// handshake frame.
func (c *Codec) Encode(pkt *NovaServerPacket, params novaproto.HeaderParams) ([]byte, error) {
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
	h := headerFromParams(params)
	if params.IsEncrypted {
		return c.frame.Seal(&h, metaBytes, pkt.Payload)
	}
	return frame.MarshalPlain(&h, metaBytes, pkt.Payload)
}

// Decode parses a wire frame into a NovaServerPacket. The returned
// HeaderParams reflects the framing metadata that was on the wire.
// Plain and encrypted frames are dispatched automatically based on the
// IsEncrypted byte at offset 0.
func (c *Codec) Decode(frameBytes []byte) (*NovaServerPacket, novaproto.HeaderParams, error) {
	if len(frameBytes) < 1 {
		return nil, novaproto.HeaderParams{}, errors.New("c2s: empty frame")
	}

	var (
		header    *novaproto.Header
		metaBytes []byte
		payload   []byte
		err       error
	)
	if frameBytes[0] == 0 {
		header, metaBytes, payload, err = frame.UnmarshalPlain(frameBytes)
	} else {
		header, metaBytes, payload, err = c.frame.Open(frameBytes)
	}
	if err != nil {
		return nil, novaproto.HeaderParams{}, err
	}

	var meta Metadata
	if err := serializer.Unmarshal(metaBytes, &meta); err != nil {
		return nil, novaproto.HeaderParams{}, err
	}
	return &NovaServerPacket{Meta: meta, Payload: payload}, paramsFromHeader(header), nil
}

func headerFromParams(p novaproto.HeaderParams) novaproto.Header {
	return novaproto.Header{
		IsEncrypted:    p.IsEncrypted,
		Nonce:          p.Nonce,
		FragmentNum:    p.FragmentNum,
		FragmentsCount: p.FragmentsCount,
	}
}

func paramsFromHeader(h *novaproto.Header) novaproto.HeaderParams {
	return novaproto.HeaderParams{
		Nonce:          h.Nonce,
		FragmentNum:    h.FragmentNum,
		FragmentsCount: h.FragmentsCount,
		IsEncrypted:    h.IsEncrypted,
	}
}
