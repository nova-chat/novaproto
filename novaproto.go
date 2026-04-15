// Package novaproto holds shared protocol constants, options and the
// wire-level Header used by the two independent codec layers:
//
//   - novaproto/c2c — client↔client end-to-end layer (NovaPacket).
//   - novaproto/c2s — client↔server transport layer (NovaServerPacket).
//
// Both layers share the same wire Header and encryption primitive
// (see novaproto/internal/frame). Clients stack them — a NovaPacket
// encoded by c2c becomes the Payload of a NovaServerPacket encoded by c2s.
// Servers only touch the c2s layer and treat the inner blob as opaque.
package novaproto

import (
	"errors"

	"github.com/nova-chat/novaproto/serializer"
)

const (
	// Magic identifies the protocol on the wire.
	Magic uint32 = 0x4E4F5641 // "NOVA"
	// Version is the wire-format version.
	Version uint32 = 1
)

// Options tunes padding and random-prefix behavior for DPI resistance.
// Same shape for every codec layer; each layer gets its own instance.
type Options struct {
	// PadTo rounds the plaintext inner body up to a multiple of this many
	// bytes. 0 disables.
	PadTo int
	// PadMax adds a uniform-random 0..PadMax bytes on top of PadTo.
	// 0 disables.
	PadMax int
	// PrefixMax caps the random-prefix length. The actual length is
	// derived from the key (session-fixed) and stays in [0, PrefixMax].
	// 0 disables.
	PrefixMax int
}

// MaxPrefixLen is the absolute cap for Options.PrefixMax.
const MaxPrefixLen = 64

// NonceSize is the length of the AES-GCM nonce carried in a Header.
const NonceSize = 12

// HeaderSize is the fixed serialized size of a Header on the wire.
const HeaderSize = 1 + NonceSize + 4 + 4 + 4 + 2 + 2 // 29

// HeaderParams is the set of Header fields a caller controls on Encode
// and receives on Decode. Magic, Version and Length are filled in by
// the codec and are not exposed here.
//
// Nonce must be unique per (key, frame) for encrypted frames —
// reusing a nonce with the same key breaks AES-GCM. Callers are
// expected to draw it from crypto/rand for each Encode call. For plain
// frames Nonce is a free field the caller may set to zero.
type HeaderParams struct {
	Nonce          [NonceSize]byte
	FragmentNum    int16
	FragmentsCount int16
	IsEncrypted    bool
}

// Header is the outer 29-byte frame header.
//
// Some fields are filled in by the frame primitive itself during sealing
// (Nonce, Magic, Version, Length); the rest come from the caller via
// HeaderParams (IsEncrypted, FragmentNum, FragmentsCount).
//
// Wire position: Header occupies the first HeaderSize bytes of the wire
// frame. IsEncrypted (one byte) and Nonce travel in the clear — this
// lets a receiver dispatch plain vs. encrypted frames without a key by
// reading byte 0. In encrypted frames every byte after the nonce is
// XOR-obfuscated with a per-session keystream and authenticated as AEAD
// additional data; in plain frames the whole Header is on the wire in
// the clear.
//
// FragmentNum / FragmentsCount let the sender split one logical message
// across multiple frames. For unfragmented messages set FragmentsCount = 1
// and FragmentNum = 0.
type Header struct {
	IsEncrypted    bool
	Nonce          [NonceSize]byte
	Magic          uint32
	Version        uint32
	Length         uint32
	FragmentNum    int16
	FragmentsCount int16
}

// Marshal serializes the Header via the serializer package.
func (h *Header) Marshal() ([]byte, error) {
	return serializer.Marshal(h)
}

// UnmarshalHeader parses the first HeaderSize bytes of buf as a Header.
func UnmarshalHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderSize {
		return nil, errors.New("novaproto: header too short")
	}
	var h Header
	if err := serializer.Unmarshal(buf[:HeaderSize], &h); err != nil {
		return nil, err
	}
	return &h, nil
}
