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
// Both directions support multiple in-flight packets simultaneously:
//
//   - SendPacket may be called concurrently from many goroutines.
//     Each call gets a fresh PacketNonce and an independent
//     io.WriteCloser. Frames of different packets interleave on the
//     wire (the Wire's own writeMu serializes individual frame writes,
//     so frames stay atomic on the wire even though packets do not).
//
//   - On the receive side, a single read worker demultiplexes incoming
//     frames by PacketNonce so each in-flight packet's reader receives
//     only its own bytes. ReceivePacket returns each new packet as it
//     starts; callers typically spawn one goroutine per packet to
//     drain readers in parallel.
//
// Sending:
//
//	w := ps.SendPacket()
//	io.Copy(w, src) // streamed into wire frames as data is written
//	w.Close()       // emits the empty terminating frame
//
// Receiving:
//
//	for {
//	    r, err := ps.ReceivePacket()
//	    if err != nil { ... }
//	    go drain(r) // spawn per-packet drainer to avoid HoL blocking
//	}
//
// Head-of-line blocking warning: the read worker writes incoming
// frame content into a per-packet io.Pipe. If a consumer stops
// reading one packet's reader, the pipe write blocks and stalls the
// entire stream — no other packets can be processed until that
// reader is drained or the wire errors out. ALWAYS drain returned
// readers (or close them to signal you're done) and call
// ReceivePacket promptly so new packets get picked up before the
// channel buffer fills.
type PacketStream struct {
	wire Wire

	// Send side. nextPkt is the only state, accessed atomically.
	nextPkt atomic.Uint32

	// Receive side.
	packets     chan *incomingPacket
	readErr     atomic.Pointer[error]
	startReader sync.Once
}

// incomingPacketBuffer is the depth of the queue of newly-arrived
// packets waiting to be picked up by ReceivePacket. Larger means more
// new packets can be absorbed before the read worker stalls on a
// slow consumer; this only buffers channel slots, not packet content.
const incomingPacketBuffer = 64

// NewPacketStream wraps a Wire in a packet multiplexer. The read
// worker is started lazily on the first ReceivePacket call, so a
// write-only user pays no goroutine cost.
func NewPacketStream(wire Wire) *PacketStream {
	return &PacketStream{
		wire:    wire,
		packets: make(chan *incomingPacket, incomingPacketBuffer),
	}
}

// SendPacket returns an io.WriteCloser for one outgoing packet. Safe
// to call concurrently from multiple goroutines; each call returns a
// distinct writer with a fresh PacketNonce, and writes from different
// writers are independently framed and interleaved on the wire.
//
// Close MUST be called on every returned writer to emit the empty
// terminating frame; forgetting Close orphans the packet on the
// receiver side (its inflight entry stays alive until the wire
// errors out).
//
// A single packetWriter is NOT safe for concurrent Write calls — if
// you need parallel writes, use multiple packets, not multiple
// writers on the same packet.
func (ps *PacketStream) SendPacket() io.WriteCloser {
	return &packetWriter{
		ps:          ps,
		packetNonce: ps.nextPkt.Add(1),
	}
}

// ReceivePacket blocks until the next incoming packet begins and
// returns an io.Reader for its content. The reader yields bytes as
// frames arrive and returns io.EOF when the terminating frame lands.
//
// Returns the terminal wire error once the read worker has seen one.
//
// Multiple readers may exist simultaneously when the peer is
// multiplexing — the typical pattern is one drain goroutine per
// returned reader. Sequential drain (calling ReadAll inline before
// the next ReceivePacket) is unsafe whenever the peer overlaps
// packets, because pending frames for unsipped packets can deadlock
// the read worker.
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
// bytes and pushes them through the wire.
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

// Close sends the empty terminating frame so the receiver knows the
// packet is complete. Safe to call multiple times — only the first
// Close emits the frame.
func (pw *packetWriter) Close() error {
	if pw.closed {
		return nil
	}
	pw.closed = true

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
	reader         *io.PipeReader
	writer         *io.PipeWriter
	packetNonce    uint32
	lastFrameNonce uint32
	// discarding becomes true after the consumer's reader was closed
	// early; subsequent frames for this packet are read off the wire
	// but their content is dropped instead of being written into the
	// (already-closed) pipe. The inflight entry is removed when the
	// packet's terminating frame arrives.
	discarding bool
}

func (ps *PacketStream) readLoop() {
	defer close(ps.packets)

	inflight := make(map[uint32]*incomingPacket)

	// failAll is the deathbed cleanup for genuinely fatal transport
	// errors (EOF, broken connection, unrecoverable framing
	// corruption). It wakes up every consumer blocked on an in-flight
	// packet's pipe with the error, stores the error so subsequent
	// ReceivePacket calls return it, and then the caller returns from
	// readLoop (which closes ps.packets via the defer above).
	//
	// Per-packet errors (ErrFrameDecrypt, non-monotonic FrameNonce
	// within one packet, consumer-side pipe write failure) do NOT
	// call failAll — they fail just that one packet via failPacket
	// below and the loop keeps reading.
	failAll := func(err error) {
		ps.readErr.Store(&err)
		for _, p := range inflight {
			_ = p.writer.CloseWithError(err)
		}
	}

	// failPacket marks one packet (identified by hdr.PacketNonce) as
	// failed with err, surfacing it to the consumer:
	//   - if the packet is already in inflight, close its pipe with
	//     err and mark it discarding so subsequent frames for it are
	//     dropped silently
	//   - if it's the first frame of a packet not yet known to the
	//     consumer, create a phantom entry, push it to the packets
	//     channel and immediately CloseWithError so the consumer's
	//     first Read returns the error — this way the caller learns
	//     about every dropped packet instead of having them vanish
	// If hdr.IsTerminating is set, the inflight entry is removed too.
	failPacket := func(hdr FrameHeader, err error) {
		pkt, ok := inflight[hdr.PacketNonce]
		if !ok {
			pr, pw := io.Pipe()
			pkt = &incomingPacket{
				reader:         pr,
				writer:         pw,
				packetNonce:    hdr.PacketNonce,
				lastFrameNonce: hdr.FrameNonce,
				discarding:     true,
			}
			inflight[hdr.PacketNonce] = pkt
			_ = pkt.writer.CloseWithError(err)
			ps.packets <- pkt
		} else if !pkt.discarding {
			pkt.discarding = true
			_ = pkt.writer.CloseWithError(err)
		}
		if hdr.IsTerminating {
			delete(inflight, hdr.PacketNonce)
		}
	}

	for {
		hdr, content, err := ps.wire.ReadFrame()
		if err != nil {
			if errors.Is(err, ErrFrameDecrypt) {
				// Per-frame decrypt failure: wire is positioned at
				// the next frame, so we keep reading. The affected
				// packet is failed for its consumer.
				failPacket(hdr, err)
				continue
			}
			failAll(err)
			return
		}

		pkt, ok := inflight[hdr.PacketNonce]
		if !ok {
			// First frame of a new packet. Could be either a regular
			// content frame or, for an empty packet, the terminating
			// frame itself — handle both by creating the entry and
			// pushing it to the consumer; the terminating-frame branch
			// below then closes the pipe immediately on this same
			// iteration.
			pr, pw := io.Pipe()
			pkt = &incomingPacket{
				reader:         pr,
				writer:         pw,
				packetNonce:    hdr.PacketNonce,
				lastFrameNonce: hdr.FrameNonce,
			}
			inflight[hdr.PacketNonce] = pkt
			// Hand the reader to a consumer BEFORE writing into the
			// pipe — otherwise the pipe write blocks with no consumer
			// attached. If the packets channel is full the read loop
			// stalls until ReceivePacket drains a slot.
			ps.packets <- pkt
		} else {
			if hdr.FrameNonce <= pkt.lastFrameNonce {
				// Per-packet invariant violation. Fail just this
				// packet, keep the wire alive for unrelated packets.
				invErr := fmt.Errorf("packetstream: non-monotonic frame nonce %d after %d in packet %d",
					hdr.FrameNonce, pkt.lastFrameNonce, hdr.PacketNonce)
				failPacket(hdr, invErr)
				continue
			}
			pkt.lastFrameNonce = hdr.FrameNonce
		}

		if hdr.IsTerminating {
			if !pkt.discarding {
				_ = pkt.writer.Close()
			}
			delete(inflight, hdr.PacketNonce)
			continue
		}

		if len(content) > 0 && !pkt.discarding {
			if _, err := pkt.writer.Write(content); err != nil {
				// Consumer closed the reader early. Switch the packet
				// to discarding mode: keep its entry in inflight so
				// subsequent frames are matched and dropped, until
				// the terminating frame arrives and removes it.
				pkt.discarding = true
				_ = pkt.writer.CloseWithError(err)
			}
		}
	}
}
