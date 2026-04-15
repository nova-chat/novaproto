// Package frame implements the shared low-level frame primitive: AEAD
// encryption, header marshalling, XOR header obfuscation, random prefix and
// padding. c2c and c2s both wrap this primitive with their own packet types
// and metadata layouts.
package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/nova-chat/novaproto"
)

const (
	// nonceSize is the AES-GCM nonce length and matches novaproto.NonceSize.
	nonceSize = novaproto.NonceSize
	// obfsOffset marks where the obfuscated region starts within a Header:
	// after the 1-byte IsEncrypted flag and the 12-byte Nonce.
	obfsOffset = 1 + nonceSize
	// obfsSize is the number of Header bytes that are XOR-obfuscated and
	// authenticated as AEAD AAD.
	obfsSize = novaproto.HeaderSize - obfsOffset
)

// Codec is the shared frame primitive. Seal encrypts (meta || payload) into
// a wire frame; Open reverses it. Both meta and payload are opaque byte
// blobs — callers serialize their own metadata layouts.
type Codec struct {
	aead      cipher.AEAD
	obfsKey   []byte
	prefixLen int
	padTo     int
	padMax    int
}

func NewCodec(key []byte, opts *novaproto.Options) (*Codec, error) {
	if len(key) != 32 {
		return nil, errors.New("frame: key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &Codec{
		aead:    aead,
		obfsKey: deriveSubkey(key, "novaproto/obfs/v1"),
	}
	if opts != nil {
		if opts.PadTo < 0 || opts.PadMax < 0 || opts.PrefixMax < 0 {
			return nil, errors.New("frame: negative option value")
		}
		if opts.PrefixMax > novaproto.MaxPrefixLen {
			return nil, errors.New("frame: PrefixMax exceeds MaxPrefixLen")
		}
		c.padTo = opts.PadTo
		c.padMax = opts.PadMax
		if opts.PrefixMax > 0 {
			pk := deriveSubkey(key, "novaproto/prefix/v1")
			c.prefixLen = int(pk[0]) % (opts.PrefixMax + 1)
		}
	}
	return c, nil
}

// Seal encrypts (meta || payload) into a wire frame. The caller-supplied
// header provides framing metadata (FragmentNum, FragmentsCount,
// TotalSize); Seal overwrites IsEncrypted, Nonce, Magic, Version and
// Length with frame-level values before marshalling.
//
// Wire layout: [header HeaderSize | prefix prefixLen | ciphertext].
func (c *Codec) Seal(header *novaproto.Header, meta, payload []byte) ([]byte, error) {
	if header == nil {
		return nil, errors.New("frame: nil header")
	}
	if len(meta) > 0xFFFF {
		return nil, errors.New("frame: meta too large")
	}
	inner, err := c.buildInner(meta, payload)
	if err != nil {
		return nil, err
	}

	header.IsEncrypted = true
	header.Magic = novaproto.Magic
	header.Version = novaproto.Version
	header.Length = uint32(len(inner) + c.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, header.Nonce[:]); err != nil {
		return nil, err
	}

	headerBuf, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	ct := c.aead.Seal(nil, header.Nonce[:], inner, headerBuf[obfsOffset:])

	ks := headerKeystream(c.obfsKey, header.Nonce[:])
	for i := 0; i < obfsSize; i++ {
		headerBuf[obfsOffset+i] ^= ks[i]
	}

	out := make([]byte, novaproto.HeaderSize+c.prefixLen+len(ct))
	copy(out[:novaproto.HeaderSize], headerBuf)
	if c.prefixLen > 0 {
		if _, err := io.ReadFull(rand.Reader, out[novaproto.HeaderSize:novaproto.HeaderSize+c.prefixLen]); err != nil {
			return nil, err
		}
	}
	copy(out[novaproto.HeaderSize+c.prefixLen:], ct)
	return out, nil
}

// Open reverses Seal and returns (header, meta, payload).
func (c *Codec) Open(frame []byte) (*novaproto.Header, []byte, []byte, error) {
	if len(frame) < novaproto.HeaderSize+c.prefixLen+c.aead.Overhead() {
		return nil, nil, nil, errors.New("frame: too short")
	}

	headerBuf := make([]byte, novaproto.HeaderSize)
	copy(headerBuf, frame[:novaproto.HeaderSize])

	ks := headerKeystream(c.obfsKey, headerBuf[1:1+nonceSize])
	for i := 0; i < obfsSize; i++ {
		headerBuf[obfsOffset+i] ^= ks[i]
	}

	header, err := novaproto.UnmarshalHeader(headerBuf)
	if err != nil {
		return nil, nil, nil, err
	}
	if !header.IsEncrypted {
		return nil, nil, nil, errors.New("frame: not an encrypted frame")
	}
	if header.Magic != novaproto.Magic {
		return nil, nil, nil, errors.New("frame: bad magic")
	}
	if header.Version != novaproto.Version {
		return nil, nil, nil, errors.New("frame: unsupported version")
	}

	ctStart := novaproto.HeaderSize + c.prefixLen
	if int(header.Length) != len(frame)-ctStart {
		return nil, nil, nil, errors.New("frame: length mismatch")
	}

	pt, err := c.aead.Open(nil, header.Nonce[:], frame[ctStart:], headerBuf[obfsOffset:])
	if err != nil {
		return nil, nil, nil, err
	}
	meta, payload, err := parseInner(pt)
	if err != nil {
		return nil, nil, nil, err
	}
	return header, meta, payload, nil
}

// Inner plaintext layout:
//
//	[padLen u16 | metaLen u16 | meta | payload | padding(padLen)]
func (c *Codec) buildInner(meta, payload []byte) ([]byte, error) {
	core := 4 + len(meta) + len(payload)
	pad, err := c.padSize(core)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, core+pad)
	binary.BigEndian.PutUint16(buf[0:], uint16(pad))
	binary.BigEndian.PutUint16(buf[2:], uint16(len(meta)))
	copy(buf[4:], meta)
	copy(buf[4+len(meta):], payload)
	if pad > 0 {
		if _, err := io.ReadFull(rand.Reader, buf[core:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func parseInner(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, errors.New("frame: inner truncated")
	}
	pad := int(binary.BigEndian.Uint16(buf[0:]))
	if pad > len(buf)-4 {
		return nil, nil, errors.New("frame: padding out of bounds")
	}
	metaLen := int(binary.BigEndian.Uint16(buf[2:]))
	coreEnd := len(buf) - pad
	if 4+metaLen > coreEnd {
		return nil, nil, errors.New("frame: meta length out of bounds")
	}
	meta := append([]byte(nil), buf[4:4+metaLen]...)
	payload := append([]byte(nil), buf[4+metaLen:coreEnd]...)
	return meta, payload, nil
}

func (c *Codec) padSize(coreLen int) (int, error) {
	pad := 0
	if c.padTo > 0 {
		if rem := coreLen % c.padTo; rem != 0 {
			pad += c.padTo - rem
		}
	}
	if c.padMax > 0 {
		var b [2]byte
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return 0, err
		}
		pad += int(binary.BigEndian.Uint16(b[:])) % (c.padMax + 1)
	}
	if pad > 0xFFFF {
		pad = 0xFFFF
	}
	return pad, nil
}

func deriveSubkey(key []byte, label string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	return h.Sum(nil)
}

func headerKeystream(obfsKey, nonce []byte) []byte {
	h := hmac.New(sha256.New, obfsKey)
	h.Write([]byte("hdr"))
	h.Write(nonce)
	return h.Sum(nil)[:obfsSize]
}
