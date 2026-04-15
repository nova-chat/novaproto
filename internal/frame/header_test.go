package frame

import (
	"testing"
)

func TestHeaderSizeMatchesSerialized(t *testing.T) {
	h := &Header{FragmentNum: 3, FragmentsCount: 5, TotalSize: 1024}
	buf, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(buf) != HeaderSize {
		t.Errorf("serialized size: got %d, want %d", len(buf), HeaderSize)
	}
}

func TestHeaderRoundtrip(t *testing.T) {
	in := &Header{FragmentNum: 7, FragmentsCount: 12, TotalSize: 65536}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	tail := []byte("trailing metadata bytes")
	got, rest, err := UnmarshalHeader(append(buf, tail...))
	if err != nil {
		t.Fatalf("UnmarshalHeader: %v", err)
	}
	if *got != *in {
		t.Errorf("header: got %+v, want %+v", *got, *in)
	}
	if string(rest) != string(tail) {
		t.Errorf("tail: got %q, want %q", rest, tail)
	}
}

func TestUnmarshalHeaderRejectsShort(t *testing.T) {
	if _, _, err := UnmarshalHeader(make([]byte, HeaderSize-1)); err == nil {
		t.Error("accepted short buffer")
	}
}
