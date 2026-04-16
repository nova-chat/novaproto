package novaproto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/nova-chat/novaproto/serializer"
)

// NovaWireStreamCipher wraps any Wire (typically a NovaWireStream)
// with optional AES-GCM per-frame encryption.
//
// It is designed for late key installation: create it before the
// handshake, run plain frames through it unchanged, call SetKey once
// the session key is derived, and subsequent WriteFrame calls seal the
// content automatically. Per-frame behavior:
//
//	ReadFrame  — reads a frame from the inner stream. If
//	             FrameHeader.IsEncrypted is true, decrypts the content;
//	             if false, returns it unchanged. An encrypted frame
//	             received before SetKey produces an error.
//
//	WriteFrame — if a key is installed, seals the content with AES-GCM
//	             and forces IsEncrypted = true on the outgoing header.
//	             Otherwise passes the frame through with
//	             IsEncrypted = false.
//
// The serialized FrameHeader (after Seal has set ContentSize to the
// sealed length) is passed as AEAD additional data, so any in-flight
// modification to header fields — flags, nonces, content size — fails
// the Open on the other side.
//
// AES-GCM nonce is derived deterministically from PacketNonce and
// FrameNonce. The caller MUST ensure the (PacketNonce, FrameNonce)
// pair is unique across the lifetime of a key — reusing a nonce with
// the same key catastrophically breaks AES-GCM. A monotonic
// PacketNonce counter is the simplest way to guarantee this;
// random u32 PacketNonce gives only ~2^16 collision-free packets per
// key (birthday bound).
type NovaWireStreamCipher struct {
	inner Wire

	mu   sync.RWMutex
	aead cipher.AEAD
}

// NewNovaWireStreamCipher wraps an inner frame stream. No key is
// installed initially — reads and writes pass through until SetKey is
// called.
func NewNovaWireStreamCipher(inner Wire) *NovaWireStreamCipher {
	return &NovaWireStreamCipher{inner: inner}
}

// SetKey installs or replaces the session key. Pass nil to disable
// encryption and fall back to pass-through.
func (c *NovaWireStreamCipher) SetKey(key []byte) error {
	var aead cipher.AEAD
	if key != nil {
		if len(key) != 32 {
			return errors.New("wirecipher: key must be 32 bytes (AES-256)")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("wirecipher: new cipher: %w", err)
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("wirecipher: new GCM: %w", err)
		}
	}
	c.mu.Lock()
	c.aead = aead
	c.mu.Unlock()
	return nil
}

// HasKey reports whether a session key is currently installed.
func (c *NovaWireStreamCipher) HasKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aead != nil
}

// ReadFrame reads one frame from the inner stream, decrypting its
// content if FrameHeader.IsEncrypted is set.
func (c *NovaWireStreamCipher) ReadFrame() (FrameHeader, []byte, error) {
	hdr, content, err := c.inner.ReadFrame()
	if err != nil {
		return hdr, nil, err
	}
	if !hdr.IsEncrypted {
		return hdr, content, nil
	}

	c.mu.RLock()
	aead := c.aead
	c.mu.RUnlock()
	if aead == nil {
		return hdr, nil, fmt.Errorf("wirecipher: no key installed: %w", ErrFrameDecrypt)
	}

	nonce := deriveAEADNonce(hdr)
	aad, err := serializer.Marshal(&hdr)
	if err != nil {
		return hdr, nil, fmt.Errorf("wirecipher: marshal AAD: %w", err)
	}
	plain, err := aead.Open(nil, nonce[:], content, aad)
	if err != nil {
		return hdr, nil, fmt.Errorf("wirecipher: AEAD open: %w: %w", ErrFrameDecrypt, err)
	}
	return hdr, plain, nil
}

// WriteFrame writes one frame to the inner stream, sealing the content
// if a key is installed and forcing IsEncrypted accordingly.
func (c *NovaWireStreamCipher) WriteFrame(hdr FrameHeader, content []byte) error {
	c.mu.RLock()
	aead := c.aead
	c.mu.RUnlock()

	if aead == nil {
		hdr.IsEncrypted = false
		return c.inner.WriteFrame(hdr, content)
	}

	hdr.IsEncrypted = true
	hdr.Magic = Magic
	hdr.ContentSize = uint32(len(content) + aead.Overhead())

	nonce := deriveAEADNonce(hdr)
	aad, err := serializer.Marshal(&hdr)
	if err != nil {
		return fmt.Errorf("wirecipher: marshal AAD: %w", err)
	}
	sealed := aead.Seal(nil, nonce[:], content, aad)
	return c.inner.WriteFrame(hdr, sealed)
}

// deriveAEADNonce packs (PacketNonce, FrameNonce) into a 12-byte
// AES-GCM nonce. Bytes [8:12] are reserved zero.
func deriveAEADNonce(hdr FrameHeader) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:], hdr.PacketNonce)
	binary.BigEndian.PutUint32(nonce[4:], hdr.FrameNonce)
	return nonce
}
