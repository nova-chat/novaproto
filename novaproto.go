// Package novaproto holds shared protocol constants and options used by the
// two independent codec layers:
//
//   - novaproto/c2c — client↔client end-to-end layer (NovaPacket).
//   - novaproto/c2s — client↔server transport layer (NovaServerPacket).
//
// Both layers share the same wire header format and encryption primitive
// (see novaproto/internal/frame). Clients stack them — a NovaPacket
// encoded by c2c becomes the Payload of a NovaServerPacket encoded by c2s.
// Servers only touch the c2s layer and treat the inner blob as opaque.
package novaproto

const (
	// Magic identifies the protocol on the wire.
	Magic uint32 = 0x4E4F5641 // "NOVA"
	// Version is the wire-format version.
	Version uint32 = 1
)

// Flag is the first byte of every wire frame. It tells the receiver how to
// interpret the rest of the frame without needing a Codec or the key.
type Flag uint8

const (
	FlagEncrypted Flag = 0x00
	FlagPlain     Flag = 0x01
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
