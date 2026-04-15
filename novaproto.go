package novaproto

import "github.com/google/uuid"

const (
	Magic        uint32 = 0x4E4F5641 // "NOVA"
	MaxFrameSize uint32 = 1 << 20    // 1 MB
)

// For tcp-only usage, no packet sequencing/reack
// Assume all packets are delivered in right order

const FrameHeaderSize = 4 + 4 + 4 + 4 + 1 + 1

type FrameHeader struct {
	Magic       uint32 // For protocol verification
	ContentSize uint32 // Frame size

	FrameNonce  uint32 // Id for frame, used in encryption/decryption. Each next frame must have nonce higher then previous
	PacketNonce uint32 // Id for packet, used to determine frames are the same packet, kinda message id.

	IsTerminating bool // True for last empty packet
	IsEncrypted   bool // Is frame content encrypted
}

// PacketHeader is the routing header at the start of every packet
// body. The server reads it right after stripping the wire-level
// cipher and uses TargetID to decide whether to handle the packet
// itself (TargetID == uuid.Nil) or forward it opaquely to another
// client (TargetID != uuid.Nil). PacketHeader is never end-to-end
// encrypted — only wire-encrypted via the transport cipher — so the
// server is always able to see it after decrypting a frame.
//
// Kind is an application-defined request/message type (a "server API
// method"). The library assigns no meaning to it.
//
// Magic is a sanity / version marker set to novaproto.Magic. Readers
// verify it after unmarshalling a packet header.
type PacketHeader struct {
	Magic    uint32
	TargetID uuid.UUID
	SourceID uuid.UUID
	Kind     uint64
}

// PacketHeaderSize is the fixed serialized size of a PacketHeader.
const PacketHeaderSize = 4 + 16 + 16 + 8 // 44
