package compress

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestZstdRoundtrip(t *testing.T) {
	original := []byte(strings.Repeat("hello world from novaproto ", 100))
	compressed, algo := Compress(original, 0)
	if algo != Zstd {
		t.Fatalf("expected Zstd (1), got %d", algo)
	}
	if len(compressed) >= len(original) {
		t.Errorf("not actually smaller: compressed=%d original=%d",
			len(compressed), len(original))
	}
	restored, err := Decompress(compressed, algo)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(restored, original) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestSkipTinyPayload(t *testing.T) {
	data := []byte("short")
	out, algo := Compress(data, 0)
	if algo != None {
		t.Errorf("expected None for tiny payload, got %d", algo)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("tiny payload modified")
	}
}

func TestSkipContentType(t *testing.T) {
	const imageJPEG uint32 = 100
	SkipContentTypes[imageJPEG] = true
	defer delete(SkipContentTypes, imageJPEG)

	// Highly compressible bytes, but content type says skip.
	data := bytes.Repeat([]byte("aaaa"), 1024)
	out, algo := Compress(data, imageJPEG)
	if algo != None {
		t.Errorf("expected None for skipped content type, got %d", algo)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("skipped payload should be returned unchanged")
	}
}

func TestSkipIncompressibleData(t *testing.T) {
	// Cryptographically random bytes have ~8 bits/byte entropy and do not
	// compress. Compress must recognize this via MinSavingsRatio and fall
	// back to None.
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	out, algo := Compress(data, 0)
	if algo != None {
		t.Errorf("random data should not be marked compressed, got algo=%d "+
			"(compressed=%d original=%d)", algo, len(out), len(data))
	}

	// And it must still roundtrip cleanly through Decompress.
	restored, err := Decompress(out, algo)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(restored, data) {
		t.Errorf("roundtrip mismatch for uncompressed data")
	}
}

func TestDecompressUnknownAlgo(t *testing.T) {
	_, err := Decompress([]byte{1, 2, 3}, 99)
	if err == nil {
		t.Error("expected error for unknown algorithm")
	}
}
