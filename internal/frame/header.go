package frame

import (
	"errors"

	"github.com/nova-chat/novaproto/serializer"
)

const (
	nonceSize = 12
	// HeaderSize is the fixed serialized size of a Header on the wire.
	HeaderSize = nonceSize + 4 + 4 + 4 + 2 + 2 + 4 // 32
	obfsSize   = HeaderSize - nonceSize            // 20
)

// Header is the outer 32-byte frame header.
//
// Some fields are set by the frame primitive itself during Seal (Nonce,
// Magic, Version, Length); the rest are caller-provided framing metadata
// (FragmentNum, FragmentsCount, TotalSize).
//
// Wire position: first HeaderSize bytes after the flag byte and the
// optional random prefix. The nonce travels in the clear; every byte
// after it is XOR-obfuscated with a per-session keystream and
// authenticated as AEAD additional data.
//
// FragmentNum / FragmentsCount let the sender split one logical message
// across multiple frames. For unfragmented messages set FragmentsCount = 1
// and FragmentNum = 0. TotalSize is the size in bytes of the fully
// reassembled logical payload; the receiver uses it to pre-allocate a
// buffer and sanity-check completeness.
type Header struct {
	Nonce          [nonceSize]byte
	Magic          uint32
	Version        uint32
	Length         uint32
	FragmentNum    int16
	FragmentsCount int16
	TotalSize      uint32
}

// Marshal serializes the Header via the serializer package.
func (h *Header) Marshal() ([]byte, error) {
	return serializer.Marshal(h)
}

// UnmarshalHeader parses the first HeaderSize bytes of buf as a Header.
func UnmarshalHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderSize {
		return nil, errors.New("frame: header too short")
	}
	var h Header
	if err := serializer.Unmarshal(buf[:HeaderSize], &h); err != nil {
		return nil, err
	}
	return &h, nil
}
