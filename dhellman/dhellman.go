// Package dhellman implements an X25519 Diffie–Hellman key exchange and a
// wire message clients use to swap public keys before deriving a shared
// symmetric key.
//
// Typical flow (both sides are symmetric):
//
//  1. Each side calls GenerateKeyPair to get an ephemeral X25519 keypair.
//  2. Each side marshals a HelloMessage{PublicKey} and sends it to the
//     peer (e.g. as the Payload of a c2s plain handshake frame).
//  3. On receipt of the peer's HelloMessage, each side calls
//     KeyPair.ComputeShared to get the raw DH secret, then DeriveKey to
//     expand it into a symmetric session key. Pass the concatenated
//     public keys (in a canonical order) as the HKDF salt so the derived
//     key binds to this exact session.
//
// The package uses crypto/ecdh (constant-time, curve-checked) and
// crypto/hkdf (HKDF-SHA256). It does not authenticate the exchange —
// callers must layer their own identity verification on top to prevent
// MITM.
package dhellman

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const (
	PublicKeySize = 32
	SharedKeySize = 32

	// HelloVersion is the current wire-format version of HelloMessage.
	HelloVersion uint16 = 1
)

// KeyPair is an ephemeral X25519 keypair. The private half never leaves
// the struct.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// GenerateKeyPair returns a fresh ephemeral X25519 keypair backed by
// crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{priv: priv}, nil
}

// PublicKey returns the 32-byte X25519 public half, suitable for placing
// into a HelloMessage.
func (k *KeyPair) PublicKey() [PublicKeySize]byte {
	var out [PublicKeySize]byte
	copy(out[:], k.priv.PublicKey().Bytes())
	return out
}

// ComputeShared performs the X25519 ECDH operation against the peer's
// public key and returns the raw 32-byte shared secret. The result MUST
// be passed through DeriveKey before being used as a symmetric key.
func (k *KeyPair) ComputeShared(peerPub [PublicKeySize]byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peerPub[:])
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(pub)
}

// DeriveKey expands a raw DH shared secret into a SharedKeySize-byte
// symmetric key via HKDF-SHA256. salt and info bind the derived key to
// the session and protocol context — typically salt is the concatenation
// of both peers' public keys in a canonical order, and info identifies
// the layer (e.g. []byte("novaproto/c2s/v1")).
func DeriveKey(shared, salt, info []byte) ([]byte, error) {
	if len(shared) == 0 {
		return nil, errors.New("dhellman: empty shared secret")
	}
	return hkdf.Key(sha256.New, shared, salt, string(info), SharedKeySize)
}

// HelloMessage is the single message type exchanged during the
// handshake. Both peers send one, carrying their ephemeral public key.
// The wire format is produced by the serializer package — callers pass
// *HelloMessage through serializer.Marshal / serializer.Unmarshal
// directly and check Version themselves.
type HelloMessage struct {
	Version   uint16
	PublicKey [PublicKeySize]byte
}

// NewHelloMessage builds a HelloMessage from the keypair's public half
// with the current HelloVersion.
func NewHelloMessage(kp *KeyPair) *HelloMessage {
	return &HelloMessage{
		Version:   HelloVersion,
		PublicKey: kp.PublicKey(),
	}
}
