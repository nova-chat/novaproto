package frame

import (
	"testing"
)

func TestHeaderSizeMatchesSerialized(t *testing.T) {
	h := &Header{
		Nonce:          [nonceSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Magic:          0xDEADBEEF,
		Version:        7,
		Length:         1024,
		FragmentNum:    3,
		FragmentsCount: 5,
		TotalSize:      1024,
	}
	buf, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(buf) != HeaderSize {
		t.Errorf("serialized size: got %d, want %d", len(buf), HeaderSize)
	}
}

func TestHeaderRoundtrip(t *testing.T) {
	in := &Header{
		Nonce:          [nonceSize]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 1, 2, 3, 4, 5, 6},
		Magic:          0x4E4F5641,
		Version:        1,
		Length:         4096,
		FragmentNum:    7,
		FragmentsCount: 12,
		TotalSize:      65536,
	}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := UnmarshalHeader(buf)
	if err != nil {
		t.Fatalf("UnmarshalHeader: %v", err)
	}
	if *got != *in {
		t.Errorf("header: got %+v, want %+v", *got, *in)
	}
}

func TestUnmarshalHeaderRejectsShort(t *testing.T) {
	if _, err := UnmarshalHeader(make([]byte, HeaderSize-1)); err == nil {
		t.Error("accepted short buffer")
	}
}
