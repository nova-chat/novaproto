package novaproto

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/nova-chat/novaproto/serializer"
)

// NovaWireStream is the raw framing layer over an io.ReadWriter
// (typically a net.Conn). It reads and writes one frame at a time —
// FrameHeader followed by ContentSize bytes of content — and performs
// no encryption. FrameHeader.IsEncrypted is pass-through: the caller
// (or a wrapping NovaWireStreamCipher) owns its meaning.
//
// ReadFrame and WriteFrame are each serialized by their own mutex, so
// concurrent reads or concurrent writes from multiple goroutines are
// safe. Read and write paths don't share a mutex — they can run in
// parallel.
type NovaWireStream struct {
	rwc io.ReadWriter

	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewNovaWireStream wraps an io.ReadWriter as a frame stream.
func NewNovaWireStream(rwc io.ReadWriter) *NovaWireStream {
	return &NovaWireStream{rwc: rwc}
}

// ReadFrame reads exactly one frame. Returns io.EOF when the underlying
// stream is cleanly closed on a frame boundary.
func (s *NovaWireStream) ReadFrame() (FrameHeader, []byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	var hdr FrameHeader
	hdrBuf := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(s.rwc, hdrBuf); err != nil {
		return hdr, nil, err
	}
	if err := serializer.Unmarshal(hdrBuf, &hdr); err != nil {
		return hdr, nil, fmt.Errorf("wirestream: unmarshal header: %w", err)
	}
	if hdr.Magic != Magic {
		return hdr, nil, errors.New("wirestream: bad magic")
	}
	if uint32(hdr.ContentSize)+FrameHeaderSize > MaxFrameSize {
		return hdr, nil, fmt.Errorf("wirestream: content size %d exceeds max", hdr.ContentSize)
	}

	var content []byte
	if hdr.ContentSize > 0 {
		content = make([]byte, hdr.ContentSize)
		if _, err := io.ReadFull(s.rwc, content); err != nil {
			return hdr, nil, fmt.Errorf("wirestream: read content: %w", err)
		}
	}
	return hdr, content, nil
}

// WriteFrame writes one frame. Magic and ContentSize are always set
// from the protocol constant and the content length; the caller owns
// FrameNonce, PacketNonce, IsTerminating and IsEncrypted.
func (s *NovaWireStream) WriteFrame(hdr FrameHeader, content []byte) error {
	if uint32(len(content))+FrameHeaderSize > MaxFrameSize {
		return fmt.Errorf("wirestream: content size %d exceeds max", len(content))
	}
	hdr.Magic = Magic
	hdr.ContentSize = uint32(len(content))

	hdrBuf, err := serializer.Marshal(&hdr)
	if err != nil {
		return fmt.Errorf("wirestream: marshal header: %w", err)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.rwc.Write(hdrBuf); err != nil {
		return err
	}
	if len(content) > 0 {
		if _, err := s.rwc.Write(content); err != nil {
			return err
		}
	}
	return nil
}
