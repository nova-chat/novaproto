package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Chunked streaming AEAD over plain io.WriteCloser / io.Reader.
//
// Used internally by Session to seal/open the compressed packet
// payload in fixed-size chunks so arbitrarily large packets stream
// without buffering the whole payload in memory.
//
// Wire layout of one chunk within the packet body (after the
// session's base nonce which Session writes first):
//
//	[sealedLen u32 | final u8 | sealedBytes(sealedLen)]
//
// AEAD nonce for chunk i is [baseNonce(8) | be32(i)], 12 bytes total.
// AEAD additional data for chunk i is a single byte equal to the
// final flag (0 or 1). Tampering with the final flag flips the AAD
// and fails the Open on the peer, so truncation attacks are caught.

const (
	// chunkSize is the largest plaintext block sealed in one AEAD call.
	// 64 KiB keeps per-chunk AEAD overhead negligible (16 B tag + 5 B
	// chunk header per ~64 KiB of plaintext) while keeping in-flight
	// memory small.
	chunkSize = 64 * 1024

	baseNonceSize   = 8
	chunkHeaderSize = 4 + 1 // sealedLen u32 + final u8
)

// sealingWriter wraps an io.WriteCloser with chunked AES-GCM
// streaming encryption. Writes are buffered up to chunkSize, then
// emitted as one sealed chunk with a non-final flag. Close emits
// whatever is buffered (possibly empty) as the final chunk so the
// receiver can detect truncation.
type sealingWriter struct {
	inner     io.WriteCloser
	aead      cipher.AEAD
	baseNonce [baseNonceSize]byte

	chunkIdx uint32
	buf      []byte
	closed   bool
	err      error
}

func newSealingWriter(inner io.WriteCloser, aead cipher.AEAD, baseNonce [baseNonceSize]byte) *sealingWriter {
	return &sealingWriter{
		inner:     inner,
		aead:      aead,
		baseNonce: baseNonce,
		buf:       make([]byte, 0, chunkSize),
	}
}

func (w *sealingWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("session: write on closed sealer")
	}
	if w.err != nil {
		return 0, w.err
	}

	written := 0
	for len(p) > 0 {
		space := chunkSize - len(w.buf)
		if space == 0 {
			if err := w.flush(false); err != nil {
				w.err = err
				return written, err
			}
			continue
		}
		take := space
		if take > len(p) {
			take = len(p)
		}
		w.buf = append(w.buf, p[:take]...)
		written += take
		p = p[take:]
	}
	return written, nil
}

// Close flushes the remaining buffered bytes as the final chunk
// (possibly empty) and closes the inner WriteCloser. Idempotent.
func (w *sealingWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.inner.Close()

	if w.err != nil {
		return w.err
	}
	return w.flush(true)
}

func (w *sealingWriter) flush(final bool) error {
	nonce := chunkNonce(w.baseNonce, w.chunkIdx)
	var aad [1]byte
	if final {
		aad[0] = 1
	}
	sealed := w.aead.Seal(nil, nonce[:], w.buf, aad[:])
	w.buf = w.buf[:0]
	w.chunkIdx++

	var hdr [chunkHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(sealed)))
	hdr[4] = aad[0]

	if _, err := w.inner.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.inner.Write(sealed); err != nil {
		return err
	}
	return nil
}

// openingReader wraps an io.Reader with chunked AES-GCM streaming
// decryption. It mirrors sealingWriter: reads chunk headers, opens
// the sealed bytes, yields plaintext via Read, and signals io.EOF
// once the chunk marked final is consumed. Truncation (EOF before a
// final chunk) surfaces as an error.
type openingReader struct {
	inner     io.Reader
	aead      cipher.AEAD
	baseNonce [baseNonceSize]byte

	chunkIdx uint32
	pending  []byte
	eof      bool
	err      error
}

func newOpeningReader(inner io.Reader, aead cipher.AEAD, baseNonce [baseNonceSize]byte) *openingReader {
	return &openingReader{
		inner:     inner,
		aead:      aead,
		baseNonce: baseNonce,
	}
}

func (r *openingReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for len(r.pending) == 0 {
		if r.eof {
			return 0, io.EOF
		}
		if err := r.loadChunk(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *openingReader) loadChunk() error {
	var hdr [chunkHeaderSize]byte
	if _, err := io.ReadFull(r.inner, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("session: truncated stream, missing final chunk")
		}
		return fmt.Errorf("session: read chunk header: %w", err)
	}
	sealedLen := binary.BigEndian.Uint32(hdr[0:4])
	final := hdr[4] != 0

	if sealedLen > uint32(chunkSize)+uint32(r.aead.Overhead()) {
		return fmt.Errorf("session: sealed chunk size %d exceeds max", sealedLen)
	}
	sealed := make([]byte, sealedLen)
	if _, err := io.ReadFull(r.inner, sealed); err != nil {
		return fmt.Errorf("session: read sealed bytes: %w", err)
	}

	nonce := chunkNonce(r.baseNonce, r.chunkIdx)
	var aad [1]byte
	if final {
		aad[0] = 1
	}
	plain, err := r.aead.Open(nil, nonce[:], sealed, aad[:])
	if err != nil {
		return fmt.Errorf("session: AEAD open chunk %d: %w", r.chunkIdx, err)
	}
	r.chunkIdx++
	r.pending = plain
	if final {
		r.eof = true
	}
	return nil
}

// chunkNonce packs [baseNonce(8) | be32(chunkIdx)] into a 12-byte
// AES-GCM nonce. Uniqueness within a (key, packet) pair is guaranteed
// by chunkIdx monotonicity; across packets by fresh random baseNonce.
func chunkNonce(base [baseNonceSize]byte, idx uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:baseNonceSize], base[:])
	binary.BigEndian.PutUint32(nonce[baseNonceSize:], idx)
	return nonce
}
