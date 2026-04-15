package novaproto

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// PacketStream multiplexes logical packets over a Wire. A packet is a
// sequence of frames sharing one PacketNonce, terminated by a frame
// with IsTerminating = true.
//
// Both directions are fully streaming:
//
//	SendPacket()    returns an io.WriteCloser; each Write call chunks
//	                the content into one or more frames (up to
//	                MaxFrameSize) and writes them to the wire as the
//	                caller produces bytes. Close() emits the empty
//	                terminating frame and releases the send lock.
//
//	ReceivePacket() blocks until the next packet starts, then returns
//	                an io.Reader. The reader yields the packet content
//	                as frames arrive and returns io.EOF when the
//	                terminating frame is seen. The underlying pipe
//	                back-pressures the read worker, so a slow reader
//	                throttles the wire instead of buffering in memory.
//
// SendPacket is serialized: a second SendPacket blocks until the
// previous WriteCloser is Closed. ReceivePacket must be drained to
// io.EOF before calling it again — the read worker holds on the
// current packet's pipe until the consumer reads it out.
//
// Because PacketStream takes a Wire, it runs unchanged over a plain
// NovaWireStream or a NovaWireStreamCipher — the encryption layer is
// orthogonal. You can wrap a cipher after construction and subsequent
// packets will be encrypted without touching PacketStream.
type PacketStream struct {
	wire Wire

	// Send side.
	sendMu  sync.Mutex    // held while a SendPacket writer is open
	nextPkt atomic.Uint32 // outgoing PacketNonce counter

	// Receive side.
	packets     chan *incomingPacket
	readErr     atomic.Pointer[error]
	startReader sync.Once
}

// NewPacketStream wraps a Wire in a packet multiplexer. The read
// worker is started lazily on the first ReceivePacket call, so a
// write-only user pays no goroutine cost.
func NewPacketStream(wire Wire) *PacketStream {
	return &PacketStream{
		wire:    wire,
		packets: make(chan *incomingPacket, 1),
	}
}

// SendPacket returns an io.WriteCloser that streams one outgoing
// packet. Close MUST be called to emit the terminating frame and
// release the internal send lock; forgetting Close deadlocks the
// next SendPacket.
func (ps *PacketStream) SendPacket() io.WriteCloser {
	ps.sendMu.Lock()
	return &packetWriter{
		ps:          ps,
		packetNonce: ps.nextPkt.Add(1),
	}
}

// ReceivePacket blocks until the next incoming packet begins and
// returns an io.Reader for its content. The reader yields bytes as
// frames arrive and returns io.EOF when the terminating frame lands.
// The previous reader must be drained to io.EOF before calling
// ReceivePacket again.
//
// Returns the terminal wire error once the read worker has seen one.
func (ps *PacketStream) ReceivePacket() (io.Reader, error) {
	ps.startReader.Do(func() { go ps.readLoop() })
	pkt, ok := <-ps.packets
	if !ok {
		if errp := ps.readErr.Load(); errp != nil {
			return nil, *errp
		}
		return nil, io.EOF
	}
	return pkt.reader, nil
}

// --- send side internals ---------------------------------------------

type packetWriter struct {
	ps          *PacketStream
	packetNonce uint32
	frameNonce  uint32
	closed      bool
}

// Write chunks p into frames of at most MaxFrameSize-FrameHeaderSize
// bytes and pushes them through the wire. Under a cipher wrapper,
// the wire will reject oversized content (sealed size exceeds the
// limit); callers that care about exact max-plain size can check the
// cipher's overhead before calling.
func (pw *packetWriter) Write(p []byte) (int, error) {
	if pw.closed {
		return 0, errors.New("packetstream: write on closed packet writer")
	}
	maxChunk := int(MaxFrameSize - FrameHeaderSize)

	written := 0
	for written < len(p) {
		chunk := len(p) - written
		if chunk > maxChunk {
			chunk = maxChunk
		}
		pw.frameNonce++
		hdr := FrameHeader{
			PacketNonce: pw.packetNonce,
			FrameNonce:  pw.frameNonce,
		}
		if err := pw.ps.wire.WriteFrame(hdr, p[written:written+chunk]); err != nil {
			return written, err
		}
		written += chunk
	}
	return written, nil
}

// Close sends the empty terminating frame and releases the stream's
// send lock. Safe to call multiple times — only the first Close emits
// the frame and unlocks.
func (pw *packetWriter) Close() error {
	if pw.closed {
		return nil
	}
	pw.closed = true
	defer pw.ps.sendMu.Unlock()

	pw.frameNonce++
	hdr := FrameHeader{
		PacketNonce:   pw.packetNonce,
		FrameNonce:    pw.frameNonce,
		IsTerminating: true,
	}
	return pw.ps.wire.WriteFrame(hdr, nil)
}

// --- receive side internals ------------------------------------------

type incomingPacket struct {
	reader      *io.PipeReader
	writer      *io.PipeWriter
	packetNonce uint32
}

func (ps *PacketStream) readLoop() {
	defer close(ps.packets)

	var current *incomingPacket
	var lastFrameNonce uint32

	for {
		hdr, content, err := ps.wire.ReadFrame()
		if err != nil {
			ps.readErr.Store(&err)
			if current != nil {
				_ = current.writer.CloseWithError(err)
			}
			return
		}

		if current == nil {
			// New packet begins here.
			pr, pw := io.Pipe()
			current = &incomingPacket{
				reader:      pr,
				writer:      pw,
				packetNonce: hdr.PacketNonce,
			}
			lastFrameNonce = hdr.FrameNonce
			// Hand the reader to ReceivePacket before we write into
			// the pipe, otherwise Write blocks forever with no
			// consumer attached.
			ps.packets <- current
		} else {
			if hdr.PacketNonce != current.packetNonce {
				err := fmt.Errorf("packetstream: packet nonce changed from %d to %d mid-packet",
					current.packetNonce, hdr.PacketNonce)
				_ = current.writer.CloseWithError(err)
				ps.readErr.Store(&err)
				return
			}
			if hdr.FrameNonce <= lastFrameNonce {
				err := fmt.Errorf("packetstream: non-monotonic frame nonce %d after %d",
					hdr.FrameNonce, lastFrameNonce)
				_ = current.writer.CloseWithError(err)
				ps.readErr.Store(&err)
				return
			}
			lastFrameNonce = hdr.FrameNonce
		}

		if hdr.IsTerminating {
			_ = current.writer.Close()
			current = nil
			continue
		}

		if len(content) > 0 {
			if _, err := current.writer.Write(content); err != nil {
				// The consumer closed the reader early (lost interest
				// in this packet). Drain the rest of the packet's
				// frames from the wire, then move on.
				if drainErr := ps.drainPacket(current.packetNonce); drainErr != nil {
					ps.readErr.Store(&drainErr)
					return
				}
				current = nil
			}
		}
	}
}

// drainPacket reads and discards frames until the terminating frame of
// the given packet nonce arrives. Called when the consumer closed the
// reader early; keeps the wire in sync for the next packet.
func (ps *PacketStream) drainPacket(nonce uint32) error {
	for {
		hdr, _, err := ps.wire.ReadFrame()
		if err != nil {
			return err
		}
		if hdr.PacketNonce != nonce {
			return fmt.Errorf("packetstream: unexpected packet nonce %d while draining %d",
				hdr.PacketNonce, nonce)
		}
		if hdr.IsTerminating {
			return nil
		}
	}
}
