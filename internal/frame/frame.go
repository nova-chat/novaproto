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
	nonceSize      = 12
	wireHeaderSize = 24
	obfsSize       = wireHeaderSize - nonceSize // 12 bytes XOR-obfuscated

	offNonce   = 0
	offMagic   = 12
	offVersion = 16
	offLength  = 20
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

// Seal encrypts (meta || payload) into a wire frame.
func (c *Codec) Seal(meta, payload []byte) ([]byte, error) {
	if len(meta) > 0xFFFF {
		return nil, errors.New("frame: meta too large")
	}
	inner, err := c.buildInner(meta, payload)
	if err != nil {
		return nil, err
	}

	var nonce [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	length := uint32(len(inner) + c.aead.Overhead())

	headerBuf := marshalHeader(nonce[:], length)
	ct := c.aead.Seal(nil, nonce[:], inner, headerBuf[offMagic:])

	ks := headerKeystream(c.obfsKey, nonce[:])
	for i := 0; i < obfsSize; i++ {
		headerBuf[offMagic+i] ^= ks[i]
	}

	out := make([]byte, 1+c.prefixLen+wireHeaderSize+len(ct))
	out[0] = byte(novaproto.FlagEncrypted)
	if c.prefixLen > 0 {
		if _, err := io.ReadFull(rand.Reader, out[1:1+c.prefixLen]); err != nil {
			return nil, err
		}
	}
	copy(out[1+c.prefixLen:], headerBuf)
	copy(out[1+c.prefixLen+wireHeaderSize:], ct)
	return out, nil
}

// Open reverses Seal and returns (meta, payload).
func (c *Codec) Open(frame []byte) ([]byte, []byte, error) {
	if len(frame) < 1+c.prefixLen+wireHeaderSize+c.aead.Overhead() {
		return nil, nil, errors.New("frame: too short")
	}
	if novaproto.Flag(frame[0]) != novaproto.FlagEncrypted {
		return nil, nil, errors.New("frame: not an encrypted frame")
	}
	body := frame[1+c.prefixLen:]

	headerBuf := make([]byte, wireHeaderSize)
	copy(headerBuf, body[:wireHeaderSize])

	ks := headerKeystream(c.obfsKey, headerBuf[offNonce:offNonce+nonceSize])
	for i := 0; i < obfsSize; i++ {
		headerBuf[offMagic+i] ^= ks[i]
	}

	magic := binary.BigEndian.Uint32(headerBuf[offMagic:])
	if magic != novaproto.Magic {
		return nil, nil, errors.New("frame: bad magic")
	}
	version := binary.BigEndian.Uint32(headerBuf[offVersion:])
	if version != novaproto.Version {
		return nil, nil, errors.New("frame: unsupported version")
	}
	length := binary.BigEndian.Uint32(headerBuf[offLength:])
	if int(length) != len(body)-wireHeaderSize {
		return nil, nil, errors.New("frame: length mismatch")
	}

	nonce := headerBuf[offNonce : offNonce+nonceSize]
	pt, err := c.aead.Open(nil, nonce, body[wireHeaderSize:], headerBuf[offMagic:])
	if err != nil {
		return nil, nil, err
	}
	return parseInner(pt)
}

func marshalHeader(nonce []byte, length uint32) []byte {
	buf := make([]byte, wireHeaderSize)
	copy(buf[offNonce:offNonce+nonceSize], nonce)
	binary.BigEndian.PutUint32(buf[offMagic:], novaproto.Magic)
	binary.BigEndian.PutUint32(buf[offVersion:], novaproto.Version)
	binary.BigEndian.PutUint32(buf[offLength:], length)
	return buf
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
