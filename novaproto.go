package novaproto

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
