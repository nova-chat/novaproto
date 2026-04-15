package frame

import (
	"errors"

	"github.com/nova-chat/novaproto/serializer"
)

// Header is the layer-level framing block that both c2c and c2s prepend
// to their own metadata inside a sealed frame.
//
// FragmentNum / FragmentsCount let the sender split one logical message
// across multiple frames so the receiver can reassemble them. For
// unfragmented messages set FragmentsCount = 1 and FragmentNum = 0.
//
// TotalSize is the size in bytes of the fully reassembled logical packet
// payload (sum of all fragment payloads). The receiver uses it to
// pre-allocate a buffer and sanity-check completeness.
type Header struct {
	FragmentNum    int16
	FragmentsCount int16
	TotalSize      uint32
}

// HeaderSize is the fixed serialized size of a Header on the wire.
const HeaderSize = 2 + 2 + 4

// Marshal serializes the Header via the serializer package.
func (h *Header) Marshal() ([]byte, error) {
	return serializer.Marshal(h)
}

// UnmarshalHeader parses the first HeaderSize bytes of buf as a Header
// and returns the parsed header along with the remainder of the buffer
// (typically the layer's metadata bytes).
func UnmarshalHeader(buf []byte) (*Header, []byte, error) {
	if len(buf) < HeaderSize {
		return nil, nil, errors.New("frame: header truncated")
	}
	var h Header
	if err := serializer.Unmarshal(buf[:HeaderSize], &h); err != nil {
		return nil, nil, err
	}
	return &h, buf[HeaderSize:], nil
}
