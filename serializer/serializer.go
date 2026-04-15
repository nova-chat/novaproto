// Package serializer provides a compact binary serializer/deserializer for
// Go values via reflection, with a generic-typed public API.
//
// Supported kinds: bool, all fixed-size integer types (int8..int64,
// uint8..uint64), int, uint, float32, float64, string, array, slice,
// struct (exported fields only). Byte slices and byte arrays are handled
// on a fast path. Pointers, maps, interfaces, channels, and functions are
// NOT supported — the encoder returns ErrUnsupportedKind for them.
//
// Wire format: all multi-byte integers are big-endian. Variable-length
// values (string, slice) are prefixed with a uint32 length. Structs are
// serialized in field-declaration order. int/uint are always written as
// 8 bytes for portability.
package serializer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
)

var (
	ErrShortBuffer     = errors.New("serializer: short buffer")
	ErrUnsupportedKind = errors.New("serializer: unsupported kind")
	ErrNilPointer      = errors.New("serializer: nil pointer")
	ErrTrailingBytes   = errors.New("serializer: trailing bytes after value")
)

// Marshal serializes v into a compact binary representation.
func Marshal[T any](v T) ([]byte, error) {
	return encodeValue(nil, reflect.ValueOf(v))
}

// Unmarshal parses data into *v. v must be a non-nil pointer. It is an
// error if data contains trailing bytes after the decoded value.
func Unmarshal[T any](data []byte, v *T) error {
	if v == nil {
		return ErrNilPointer
	}
	rest, err := decodeValue(data, reflect.ValueOf(v).Elem())
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("%w: %d bytes", ErrTrailingBytes, len(rest))
	}
	return nil
}

func encodeValue(buf []byte, v reflect.Value) ([]byte, error) {
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			buf = append(buf, 1)
		} else {
			buf = append(buf, 0)
		}

	case reflect.Int8:
		buf = append(buf, byte(v.Int()))
	case reflect.Int16:
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.Int()))
	case reflect.Int32:
		buf = binary.BigEndian.AppendUint32(buf, uint32(v.Int()))
	case reflect.Int64, reflect.Int:
		buf = binary.BigEndian.AppendUint64(buf, uint64(v.Int()))

	case reflect.Uint8:
		buf = append(buf, byte(v.Uint()))
	case reflect.Uint16:
		buf = binary.BigEndian.AppendUint16(buf, uint16(v.Uint()))
	case reflect.Uint32:
		buf = binary.BigEndian.AppendUint32(buf, uint32(v.Uint()))
	case reflect.Uint64, reflect.Uint:
		buf = binary.BigEndian.AppendUint64(buf, v.Uint())

	case reflect.Float32:
		buf = binary.BigEndian.AppendUint32(buf, math.Float32bits(float32(v.Float())))
	case reflect.Float64:
		buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(v.Float()))

	case reflect.String:
		s := v.String()
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
		buf = append(buf, s...)

	case reflect.Slice:
		n := v.Len()
		buf = binary.BigEndian.AppendUint32(buf, uint32(n))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			buf = append(buf, v.Bytes()...)
			break
		}
		for i := 0; i < n; i++ {
			var err error
			buf, err = encodeValue(buf, v.Index(i))
			if err != nil {
				return nil, err
			}
		}

	case reflect.Array:
		n := v.Len()
		if v.Type().Elem().Kind() == reflect.Uint8 {
			for i := 0; i < n; i++ {
				buf = append(buf, byte(v.Index(i).Uint()))
			}
			break
		}
		for i := 0; i < n; i++ {
			var err error
			buf, err = encodeValue(buf, v.Index(i))
			if err != nil {
				return nil, err
			}
		}

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			var err error
			buf, err = encodeValue(buf, v.Field(i))
			if err != nil {
				return nil, err
			}
		}

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKind, v.Kind())
	}
	return buf, nil
}

func decodeValue(data []byte, v reflect.Value) ([]byte, error) {
	switch v.Kind() {
	case reflect.Bool:
		if len(data) < 1 {
			return nil, ErrShortBuffer
		}
		v.SetBool(data[0] != 0)
		data = data[1:]

	case reflect.Int8:
		if len(data) < 1 {
			return nil, ErrShortBuffer
		}
		v.SetInt(int64(int8(data[0])))
		data = data[1:]
	case reflect.Int16:
		if len(data) < 2 {
			return nil, ErrShortBuffer
		}
		v.SetInt(int64(int16(binary.BigEndian.Uint16(data))))
		data = data[2:]
	case reflect.Int32:
		if len(data) < 4 {
			return nil, ErrShortBuffer
		}
		v.SetInt(int64(int32(binary.BigEndian.Uint32(data))))
		data = data[4:]
	case reflect.Int64, reflect.Int:
		if len(data) < 8 {
			return nil, ErrShortBuffer
		}
		v.SetInt(int64(binary.BigEndian.Uint64(data)))
		data = data[8:]

	case reflect.Uint8:
		if len(data) < 1 {
			return nil, ErrShortBuffer
		}
		v.SetUint(uint64(data[0]))
		data = data[1:]
	case reflect.Uint16:
		if len(data) < 2 {
			return nil, ErrShortBuffer
		}
		v.SetUint(uint64(binary.BigEndian.Uint16(data)))
		data = data[2:]
	case reflect.Uint32:
		if len(data) < 4 {
			return nil, ErrShortBuffer
		}
		v.SetUint(uint64(binary.BigEndian.Uint32(data)))
		data = data[4:]
	case reflect.Uint64, reflect.Uint:
		if len(data) < 8 {
			return nil, ErrShortBuffer
		}
		v.SetUint(binary.BigEndian.Uint64(data))
		data = data[8:]

	case reflect.Float32:
		if len(data) < 4 {
			return nil, ErrShortBuffer
		}
		v.SetFloat(float64(math.Float32frombits(binary.BigEndian.Uint32(data))))
		data = data[4:]
	case reflect.Float64:
		if len(data) < 8 {
			return nil, ErrShortBuffer
		}
		v.SetFloat(math.Float64frombits(binary.BigEndian.Uint64(data)))
		data = data[8:]

	case reflect.String:
		if len(data) < 4 {
			return nil, ErrShortBuffer
		}
		n := binary.BigEndian.Uint32(data)
		data = data[4:]
		if uint64(len(data)) < uint64(n) {
			return nil, ErrShortBuffer
		}
		v.SetString(string(data[:n]))
		data = data[n:]

	case reflect.Slice:
		if len(data) < 4 {
			return nil, ErrShortBuffer
		}
		n := binary.BigEndian.Uint32(data)
		data = data[4:]
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if uint64(len(data)) < uint64(n) {
				return nil, ErrShortBuffer
			}
			b := make([]byte, n)
			copy(b, data[:n])
			v.SetBytes(b)
			data = data[n:]
			break
		}
		slice := reflect.MakeSlice(v.Type(), int(n), int(n))
		for i := 0; i < int(n); i++ {
			var err error
			data, err = decodeValue(data, slice.Index(i))
			if err != nil {
				return nil, err
			}
		}
		v.Set(slice)

	case reflect.Array:
		n := v.Len()
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if len(data) < n {
				return nil, ErrShortBuffer
			}
			for i := 0; i < n; i++ {
				v.Index(i).SetUint(uint64(data[i]))
			}
			data = data[n:]
			break
		}
		for i := 0; i < n; i++ {
			var err error
			data, err = decodeValue(data, v.Index(i))
			if err != nil {
				return nil, err
			}
		}

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			var err error
			data, err = decodeValue(data, v.Field(i))
			if err != nil {
				return nil, err
			}
		}

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKind, v.Kind())
	}
	return data, nil
}
