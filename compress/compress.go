// Package compress provides a content-aware compression helper for the
// novaproto payload layer. It attempts compression only when it's likely
// to save bytes, and returns an algorithm tag that the caller carries
// alongside the payload (e.g. as an extra field in their own packet
// metadata) and feeds back into Decompress on the receiving side.
//
// Strategy:
//
//  1. If the payload is smaller than MinSize, skip (compressor header
//     overhead > expected savings).
//  2. If contentType is in SkipContentTypes (caller-configured list of
//     already-compressed media types like image/jpeg, video/h264, zip),
//     skip.
//  3. Otherwise try zstd. If the compressed output is not at least
//     (1 - MinSavingsRatio) smaller than the input, return the original.
//
// The caller carries the returned algo alongside the payload and passes
// it to Decompress on the receiving side.
package compress

import (
	"errors"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Algorithm tags. Stored as uint8 in packet metadata.
const (
	None uint8 = 0
	Zstd uint8 = 1
)

// Tunables.
const (
	// MinSize is the smallest payload for which compression is attempted.
	// The zstd frame header is ~15 bytes; below this threshold compression
	// typically inflates the payload.
	MinSize = 64

	// MinSavingsRatio is the worst acceptable ratio of compressed to
	// original size. If len(compressed) >= len(original) * MinSavingsRatio,
	// Compress returns the original with algo=None.
	MinSavingsRatio = 0.95
)

// SkipContentTypes lists content-type values that Compress treats as
// already-compressed (images, video, archives, encrypted blobs). Callers
// populate this at startup. Not thread-safe — set once before use.
var SkipContentTypes = map[uint32]bool{}

// The zstd encoder and decoder are safe for concurrent use and reuse their
// internal state, so we keep one of each per process, created lazily.
var (
	encOnce sync.Once
	encoder *zstd.Encoder
	encErr  error

	decOnce sync.Once
	decoder *zstd.Decoder
	decErr  error
)

func getEncoder() (*zstd.Encoder, error) {
	encOnce.Do(func() {
		encoder, encErr = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderConcurrency(1),
		)
	})
	return encoder, encErr
}

func getDecoder() (*zstd.Decoder, error) {
	decOnce.Do(func() {
		decoder, decErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
		)
	})
	return decoder, decErr
}

// Compress attempts to compress data based on size, contentType hint, and
// actual achievable savings. Returns the bytes to put on the wire together
// with the algorithm tag. The caller stores the tag in metadata and feeds
// it to Decompress on receive.
func Compress(data []byte, contentType uint32) (out []byte, algo uint8) {
	if len(data) < MinSize {
		return data, None
	}
	if SkipContentTypes[contentType] {
		return data, None
	}

	enc, err := getEncoder()
	if err != nil {
		return data, None
	}
	compressed := enc.EncodeAll(data, nil)

	if float64(len(compressed)) >= float64(len(data))*MinSavingsRatio {
		return data, None
	}
	return compressed, Zstd
}

// Decompress reverses Compress. algo must match the value returned from
// Compress. When algo is None the data is returned unchanged.
func Decompress(data []byte, algo uint8) ([]byte, error) {
	switch algo {
	case None:
		return data, nil
	case Zstd:
		dec, err := getDecoder()
		if err != nil {
			return nil, err
		}
		return dec.DecodeAll(data, nil)
	default:
		return nil, errors.New("compress: unknown algorithm")
	}
}
