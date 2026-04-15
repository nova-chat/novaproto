package novaproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// packetCipherChunkSize is the largest plaintext block the packet
// cipher seals in one AEAD call. A larger chunk means fewer tag bytes
// per MB of payload but more memory buffered per in-flight packet.
// 64 KiB is a reasonable middle ground and matches TLS record sizes.
const packetCipherChunkSize = 64 * 1024

// Wire layout inside one packet when IsEncrypted=1:
//
//	[flag u8 = 1 | baseNonce 8 | chunk1 | chunk2 | ... | chunkN(final)]
//
// Chunk layout:
//
//	[sealedLen u32 | final u8 | sealedBytes(sealedLen)]
//
// Plaintext packet:
//
//	[flag u8 = 0 | raw bytes ...]
//
// AEAD nonce for chunk i: [baseNonce(8) | be32(i)].
// AEAD AAD for chunk i:   [final u8].
//
// Per-chunk nonce uniqueness comes from the random 8-byte baseNonce
// (drawn from crypto/rand at SendPacket time) plus the chunk index.
// Tampering with the chunk's final flag flips the AAD and fails the
// Open on the peer.
const (
	pktFlagPlain     byte = 0
	pktFlagEncrypted byte = 1

	pktBaseNonceSize    = 8
	pktChunkHeaderSize  = 4 + 1 // sealedLen u32 + final u8
)

// PacketStreamCipher wraps any PacketRW (typically a PacketStream)
// with optional AES-GCM per-packet encryption. It mirrors
// NovaWireStreamCipher but one layer up: the unit of encryption is a
// logical packet, chunked internally so that arbitrarily large packets
// stream without buffering the whole payload in memory.
//
// Late-key flow:
//
//	pc := NewPacketStreamCipher(inner)
//	// handshake over plain packets
//	w := pc.SendPacket(); w.Write(hello); w.Close()
//	// derive key, install it
//	pc.SetKey(sessionKey)
//	// subsequent packets are automatically encrypted end-to-end
//	w = pc.SendPacket(); io.Copy(w, bigFile); w.Close()
//
// Each outgoing packet carries a single byte at offset 0 marking it
// plain or encrypted, so mixed-mode sessions work on receive too.
type PacketStreamCipher struct {
	inner PacketRW

	mu   sync.RWMutex
	aead cipher.AEAD
}

// NewPacketStreamCipher wraps an inner packet stream. No key is
// installed initially; reads and writes pass through until SetKey is
// called.
func NewPacketStreamCipher(inner PacketRW) *PacketStreamCipher {
	return &PacketStreamCipher{inner: inner}
}

// SetKey installs or replaces the session key. Pass nil to disable
// encryption and fall back to plain pass-through.
func (pc *PacketStreamCipher) SetKey(key []byte) error {
	var aead cipher.AEAD
	if key != nil {
		if len(key) != 32 {
			return errors.New("packetcipher: key must be 32 bytes (AES-256)")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("packetcipher: new cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("packetcipher: new GCM: %w", err)
		}
	}
	pc.mu.Lock()
	pc.aead = aead
	pc.mu.Unlock()
	return nil
}

// HasKey reports whether a session key is currently installed.
func (pc *PacketStreamCipher) HasKey() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.aead != nil
}

// SendPacket returns a WriteCloser that streams one outgoing packet.
// If a key is installed, content is chunked and sealed with AES-GCM
// on the fly; otherwise the packet is written in the clear. Close
// finalizes the packet (emitting the final sealed chunk if encrypted)
// and closes the inner writer.
func (pc *PacketStreamCipher) SendPacket() io.WriteCloser {
	innerW := pc.inner.SendPacket()

	pc.mu.RLock()
	aead := pc.aead
	pc.mu.RUnlock()

	w := &encryptingPacketWriter{
		inner: innerW,
		aead:  aead,
	}
	return w
}

// ReceivePacket reads one incoming packet. If its leading flag byte
// marks it encrypted, the returned reader decrypts chunks on the fly
// (requires a key installed via SetKey). Plain packets pass through.
func (pc *PacketStreamCipher) ReceivePacket() (io.Reader, error) {
	innerR, err := pc.inner.ReceivePacket()
	if err != nil {
		return nil, err
	}

	var flag [1]byte
	if _, err := io.ReadFull(innerR, flag[:]); err != nil {
		return nil, fmt.Errorf("packetcipher: read flag: %w", err)
	}

	switch flag[0] {
	case pktFlagPlain:
		return innerR, nil
	case pktFlagEncrypted:
		pc.mu.RLock()
		aead := pc.aead
		pc.mu.RUnlock()
		if aead == nil {
			return nil, errors.New("packetcipher: encrypted packet received but no key installed")
		}
		var baseNonce [pktBaseNonceSize]byte
		if _, err := io.ReadFull(innerR, baseNonce[:]); err != nil {
			return nil, fmt.Errorf("packetcipher: read base nonce: %w", err)
		}
		return &decryptingPacketReader{
			inner:     innerR,
			aead:      aead,
			baseNonce: baseNonce,
		}, nil
	default:
		return nil, fmt.Errorf("packetcipher: unknown packet flag %#x", flag[0])
	}
}

// --- writer ----------------------------------------------------------

type encryptingPacketWriter struct {
	inner io.WriteCloser

	aead      cipher.AEAD          // nil → plain pass-through
	baseNonce [pktBaseNonceSize]byte
	baseOnce  sync.Once

	headerWritten bool
	chunkIdx      uint32
	buf           []byte
	closed        bool
	err           error
}

func (w *encryptingPacketWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("packetcipher: write on closed packet writer")
	}
	if w.err != nil {
		return 0, w.err
	}
	if !w.headerWritten {
		if err := w.writeHeader(); err != nil {
			w.err = err
			return 0, err
		}
	}
	if w.aead == nil {
		n, err := w.inner.Write(p)
		if err != nil {
			w.err = err
		}
		return n, err
	}

	written := 0
	for len(p) > 0 {
		space := packetCipherChunkSize - len(w.buf)
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

// Close finalizes the packet. In encrypted mode it emits a final chunk
// (possibly empty) so the peer can verify the packet wasn't truncated.
// Safe to call more than once — subsequent calls are no-ops.
func (w *encryptingPacketWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	defer w.inner.Close()

	if w.err != nil {
		return w.err
	}
	if !w.headerWritten {
		if err := w.writeHeader(); err != nil {
			return err
		}
	}
	if w.aead != nil {
		if err := w.flush(true); err != nil {
			return err
		}
	}
	return nil
}

func (w *encryptingPacketWriter) writeHeader() error {
	if w.aead == nil {
		if _, err := w.inner.Write([]byte{pktFlagPlain}); err != nil {
			return err
		}
		w.headerWritten = true
		return nil
	}

	// Lazily generate a fresh random base nonce on first header write.
	var hdrErr error
	w.baseOnce.Do(func() {
		if _, err := io.ReadFull(rand.Reader, w.baseNonce[:]); err != nil {
			hdrErr = fmt.Errorf("packetcipher: generate base nonce: %w", err)
		}
	})
	if hdrErr != nil {
		return hdrErr
	}

	hdr := make([]byte, 1+pktBaseNonceSize)
	hdr[0] = pktFlagEncrypted
	copy(hdr[1:], w.baseNonce[:])
	if _, err := w.inner.Write(hdr); err != nil {
		return err
	}
	w.headerWritten = true
	return nil
}

func (w *encryptingPacketWriter) flush(final bool) error {
	nonce := chunkNonce(w.baseNonce, w.chunkIdx)
	aad := [1]byte{}
	if final {
		aad[0] = 1
	}
	sealed := w.aead.Seal(nil, nonce[:], w.buf, aad[:])
	w.buf = w.buf[:0]
	w.chunkIdx++

	var chunkHdr [pktChunkHeaderSize]byte
	binary.BigEndian.PutUint32(chunkHdr[0:4], uint32(len(sealed)))
	chunkHdr[4] = aad[0]

	if _, err := w.inner.Write(chunkHdr[:]); err != nil {
		return err
	}
	if _, err := w.inner.Write(sealed); err != nil {
		return err
	}
	return nil
}

// --- reader ----------------------------------------------------------

type decryptingPacketReader struct {
	inner     io.Reader
	aead      cipher.AEAD
	baseNonce [pktBaseNonceSize]byte

	chunkIdx uint32
	pending  []byte // plaintext of the current chunk, being drained
	eof      bool
	err      error
}

func (r *decryptingPacketReader) Read(p []byte) (int, error) {
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

func (r *decryptingPacketReader) loadChunk() error {
	var chunkHdr [pktChunkHeaderSize]byte
	if _, err := io.ReadFull(r.inner, chunkHdr[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("packetcipher: truncated packet, missing final chunk")
		}
		return fmt.Errorf("packetcipher: read chunk header: %w", err)
	}
	sealedLen := binary.BigEndian.Uint32(chunkHdr[0:4])
	final := chunkHdr[4] != 0

	if sealedLen > uint32(packetCipherChunkSize)+uint32(r.aead.Overhead()) {
		return fmt.Errorf("packetcipher: sealed chunk size %d exceeds max", sealedLen)
	}
	sealed := make([]byte, sealedLen)
	if _, err := io.ReadFull(r.inner, sealed); err != nil {
		return fmt.Errorf("packetcipher: read sealed bytes: %w", err)
	}

	nonce := chunkNonce(r.baseNonce, r.chunkIdx)
	aad := [1]byte{}
	if final {
		aad[0] = 1
	}
	plain, err := r.aead.Open(nil, nonce[:], sealed, aad[:])
	if err != nil {
		return fmt.Errorf("packetcipher: AEAD open chunk %d: %w", r.chunkIdx, err)
	}
	r.chunkIdx++
	r.pending = plain
	if final {
		r.eof = true
	}
	return nil
}

// chunkNonce builds a 12-byte AES-GCM nonce as [baseNonce(8) | be32(i)].
func chunkNonce(base [pktBaseNonceSize]byte, idx uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:pktBaseNonceSize], base[:])
	binary.BigEndian.PutUint32(nonce[pktBaseNonceSize:], idx)
	return nonce
}
