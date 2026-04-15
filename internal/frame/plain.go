package frame

import (
	"errors"

	"github.com/nova-chat/novaproto"
	"github.com/nova-chat/novaproto/serializer"
)

// plainWire is the wire-level struct for unencrypted frames. Header is
// followed by serializer's standard u32-length-prefixed byte slices for
// meta and payload.
type plainWire struct {
	Header  novaproto.Header
	Meta    []byte
	Payload []byte
}

// MarshalPlain serializes a plain (unencrypted) frame. The caller
// provides Header with IsEncrypted / Nonce / FragmentNum /
// FragmentsCount set; MarshalPlain fills in Magic, Version and Length
// before serializing.
func MarshalPlain(header *novaproto.Header, meta, payload []byte) ([]byte, error) {
	if header == nil {
		return nil, errors.New("frame: nil header")
	}
	header.IsEncrypted = false
	header.Magic = novaproto.Magic
	header.Version = novaproto.Version
	header.Length = uint32(len(meta) + len(payload))
	return serializer.Marshal(&plainWire{
		Header:  *header,
		Meta:    meta,
		Payload: payload,
	})
}

// UnmarshalPlain reverses MarshalPlain. It validates that the frame is
// plain (IsEncrypted == false), Magic and Version match, and returns
// the decoded Header along with the meta and payload byte slices.
func UnmarshalPlain(frame []byte) (*novaproto.Header, []byte, []byte, error) {
	var pw plainWire
	if err := serializer.Unmarshal(frame, &pw); err != nil {
		return nil, nil, nil, err
	}
	if pw.Header.IsEncrypted {
		return nil, nil, nil, errors.New("frame: not a plain frame")
	}
	if pw.Header.Magic != novaproto.Magic {
		return nil, nil, nil, errors.New("frame: bad magic")
	}
	if pw.Header.Version != novaproto.Version {
		return nil, nil, nil, errors.New("frame: unsupported plain version")
	}
	return &pw.Header, pw.Meta, pw.Payload, nil
}
