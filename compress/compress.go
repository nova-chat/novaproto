// Package compress provides zlib compression helpers for novaproto
// payloads. One-shot batch API:
//
//	Compress   — zlib-compress a plaintext byte slice
//	Decompress — reverse Compress
//
// For streaming compression of large payloads callers should wrap
// io.Writer / io.Reader with compress/zlib directly — the session
// package uses that lower-level API internally to preserve streaming
// across large packets.
package compress

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// Compress wraps data in a zlib stream at default compression level.
// For very small or already-compressed inputs the result may be
// slightly larger than the input.
func Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, fmt.Errorf("compress: write: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("compress: close: %w", err)
	}
	return buf.Bytes(), nil
}

// Decompress reverses Compress, inflating a zlib stream into a new
// byte slice.
func Decompress(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompress: reader: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("decompress: read: %w", err)
	}
	return out, nil
}
