package novaproto

import "errors"

// ErrFrameDecrypt indicates a frame was read off the wire and its
// outer framing parsed correctly, but its content could not be
// decrypted (no key installed yet, key mismatch, AEAD tag failure,
// AAD mismatch).
//
// This is a RECOVERABLE per-frame error: the wire is positioned at
// the next frame and reading can continue. The packet layer drops
// the offending frame and, if the frame belongs to an in-flight
// packet, propagates the error to that packet's reader so the
// consumer sees it as a per-packet failure rather than a connection
// kill. The connection itself stays open and subsequent unrelated
// packets keep flowing.
//
// Wrap with fmt.Errorf("%w: ...", ErrFrameDecrypt, ...); detect with
// errors.Is(err, ErrFrameDecrypt).
var ErrFrameDecrypt = errors.New("novaproto: frame decryption failed")
