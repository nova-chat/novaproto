package novaproto

// Wire is the minimal frame-level interface. Both NovaWireStream
// (raw framing over an io.ReadWriter) and NovaWireStreamCipher
// (framing + optional AES-GCM) satisfy it, so higher-level layers —
// PacketStream in particular — can be written against Wire and run
// over a plaintext or encrypted transport interchangeably.
//
// A single Wire instance may be used concurrently by one goroutine
// reading frames and another writing frames. Two goroutines reading
// or two goroutines writing in parallel serialize internally.
type Wire interface {
	ReadFrame() (FrameHeader, []byte, error)
	WriteFrame(hdr FrameHeader, content []byte) error
}

// Compile-time guarantees that the two concrete stream types satisfy
// the Wire interface.
var (
	_ Wire = (*NovaWireStream)(nil)
	_ Wire = (*NovaWireStreamCipher)(nil)
)
