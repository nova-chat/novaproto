package compress

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestRoundtripRedundant(t *testing.T) {
	original := []byte(strings.Repeat("hello world from novaproto ", 100))
	compressed, err := Compress(original)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	if len(compressed) >= len(original) {
		t.Errorf("not actually smaller: compressed=%d original=%d",
			len(compressed), len(original))
	}
	restored, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(restored, original) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestRoundtripEmpty(t *testing.T) {
	compressed, err := Compress(nil)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	restored, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if len(restored) != 0 {
		t.Errorf("expected empty, got %d bytes", len(restored))
	}
}

func TestRoundtripRandom(t *testing.T) {
	// Cryptographically random bytes don't compress, but must still
	// roundtrip cleanly.
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	compressed, err := Compress(data)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	restored, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(restored, data) {
		t.Errorf("roundtrip mismatch for random data")
	}
}

func TestDecompressBadInput(t *testing.T) {
	_, err := Decompress([]byte{1, 2, 3, 4})
	if err == nil {
		t.Error("expected error for malformed zlib stream")
	}
}
