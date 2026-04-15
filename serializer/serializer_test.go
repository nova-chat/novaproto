package serializer

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func roundtrip[T any](t *testing.T, name string, in T) {
	t.Helper()
	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("%s Marshal: %v", name, err)
	}
	var out T
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("%s Unmarshal: %v", name, err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("%s roundtrip mismatch:\n  got:  %+v\n  want: %+v", name, out, in)
	}
}

func TestPrimitives(t *testing.T) {
	roundtrip(t, "bool-true", true)
	roundtrip(t, "bool-false", false)

	roundtrip(t, "int8", int8(-42))
	roundtrip(t, "int16", int16(-1234))
	roundtrip(t, "int32", int32(-123456789))
	roundtrip(t, "int64", int64(-9_223_372_036_854_775_808))
	roundtrip(t, "int", int(42))

	roundtrip(t, "uint8", uint8(250))
	roundtrip(t, "uint16", uint16(65000))
	roundtrip(t, "uint32", uint32(4_000_000_000))
	roundtrip(t, "uint64", uint64(18_000_000_000_000_000_000))
	roundtrip(t, "uint", uint(42))

	roundtrip(t, "float32", float32(3.14159))
	roundtrip(t, "float64", math.Pi)
}

func TestStringAndBytes(t *testing.T) {
	roundtrip(t, "string", "hello, мир 🌍")
	roundtrip(t, "empty-string", "")
	roundtrip(t, "bytes", []byte{0x00, 0x01, 0xFF, 0xFE})
	roundtrip(t, "empty-bytes", []byte{})

	// Large byte slice to exercise the fast path.
	big := bytes.Repeat([]byte{0xAB}, 100_000)
	roundtrip(t, "big-bytes", big)
}

func TestSlicesOfNonBytes(t *testing.T) {
	roundtrip(t, "int32-slice", []int32{1, -2, 3, -4, 5})
	roundtrip(t, "string-slice", []string{"a", "", "bb", "ccc"})
	roundtrip(t, "nested-slice", [][]int{{1, 2}, {}, {3, 4, 5}})
	roundtrip(t, "empty-slice", []string{})
}

func TestArrays(t *testing.T) {
	roundtrip(t, "byte-array", [5]byte{1, 2, 3, 4, 5})
	roundtrip(t, "int-array", [3]int32{-1, 0, 1})
}

func TestStructs(t *testing.T) {
	type Inner struct {
		N int32
		S string
	}
	type Outer struct {
		Flag   bool
		Count  uint64
		Name   string
		Blob   []byte
		Items  []Inner
		Sizes  [4]uint16
		Hidden int // exported — stored
	}

	v := Outer{
		Flag:   true,
		Count:  42,
		Name:   "novaproto",
		Blob:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Items:  []Inner{{N: 1, S: "one"}, {N: 2, S: "two"}},
		Sizes:  [4]uint16{10, 20, 30, 40},
		Hidden: 7,
	}
	roundtrip(t, "nested-struct", v)
}

func TestStructUnexportedFieldsIgnored(t *testing.T) {
	type S struct {
		Public  int32
		private int32
	}
	in := S{Public: 42}
	in.private = 99 // must not affect wire format

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out S
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Public != 42 {
		t.Errorf("Public: got %d, want 42", out.Public)
	}
	if out.private != 0 {
		t.Errorf("private should stay zero, got %d", out.private)
	}
}

func TestUUIDStructIntegration(t *testing.T) {
	// uuid.UUID is type UUID [16]byte — exercised via the array fast path.
	type Msg struct {
		ID      uuid.UUID
		Name    string
		Payload []byte
	}
	in := Msg{
		ID:      uuid.New(),
		Name:    "greeting",
		Payload: []byte("hello"),
	}
	roundtrip(t, "uuid-struct", in)
}

func TestShortBuffer(t *testing.T) {
	var out int64
	err := Unmarshal([]byte{1, 2, 3}, &out) // need 8 bytes
	if !errors.Is(err, ErrShortBuffer) {
		t.Errorf("expected ErrShortBuffer, got %v", err)
	}
}

func TestTrailingBytesRejected(t *testing.T) {
	b, err := Marshal(int32(42))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b = append(b, 0xFF) // extra byte
	var out int32
	err = Unmarshal(b, &out)
	if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("expected ErrTrailingBytes, got %v", err)
	}
}

func TestUnsupportedKindRejected(t *testing.T) {
	// Maps are not supported.
	_, err := Marshal(map[string]int{"a": 1})
	if !errors.Is(err, ErrUnsupportedKind) {
		t.Errorf("expected ErrUnsupportedKind, got %v", err)
	}
}
