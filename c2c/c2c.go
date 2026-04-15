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

// NovaPacket is the user-facing end-to-end packet. Framing metadata
// (nonce, fragmentation, encryption flag) is passed separately as
// novaproto.HeaderParams to Encode / returned from Decode.
type NovaPacket struct {
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

// Encode serializes a NovaPacket into a wire frame. If params.IsEncrypted
// is true the frame is sealed with the codec's end-to-end key; otherwise
// it is emitted in the clear (plain mode).
func (c *Codec) Encode(pkt *NovaPacket, params novaproto.HeaderParams) ([]byte, error) {
	if pkt == nil {
		return nil, errors.New("c2c: nil packet")
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

// Decode parses a wire frame into a NovaPacket. The returned
// HeaderParams reflects the framing metadata that was on the wire.
// Plain and encrypted frames are dispatched automatically based on the
// IsEncrypted byte at offset 0.
func (c *Codec) Decode(frameBytes []byte) (*NovaPacket, novaproto.HeaderParams, error) {
	if len(frameBytes) < 1 {
		return nil, novaproto.HeaderParams{}, errors.New("c2c: empty frame")
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
	return &NovaPacket{Meta: meta, Payload: payload}, paramsFromHeader(header), nil
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
