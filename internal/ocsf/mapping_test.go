package ocsf

import (
	"math"
	"testing"
)

// TestAsString exercises AsString across all supported types and edge cases.
func TestAsString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   any
		want    any // nil means we expect the result to be nil
		wantErr bool
	}{
		// nil passthrough
		{name: "nil", input: nil, want: nil, wantErr: false},

		// string passthrough
		{name: "string", input: "hello", want: "hello", wantErr: false},
		{name: "empty string", input: "", want: "", wantErr: false},

		// []byte → string
		{name: "bytes", input: []byte("world"), want: "world", wantErr: false},
		{name: "empty bytes", input: []byte{}, want: "", wantErr: false},

		// numeric stringification
		{name: "int", input: int(42), want: "42", wantErr: false},
		{name: "int negative", input: int(-7), want: "-7", wantErr: false},
		{name: "int32", input: int32(100), want: "100", wantErr: false},
		{name: "int64", input: int64(1<<40), want: "1099511627776", wantErr: false},
		{name: "uint", input: uint(9), want: "9", wantErr: false},
		{name: "uint32", input: uint32(math.MaxUint32), want: "4294967295", wantErr: false},
		{name: "uint64", input: uint64(math.MaxUint64), want: "18446744073709551615", wantErr: false},
		{name: "float32", input: float32(3.14), want: "3.14", wantErr: false},
		{name: "float64", input: float64(2.718), want: "2.718", wantErr: false},
		{name: "bool true", input: bool(true), want: "true", wantErr: false},
		{name: "bool false", input: bool(false), want: "false", wantErr: false},

		// unsupported type
		{name: "struct", input: struct{}{}, want: nil, wantErr: true},
		{name: "slice int", input: []int{1, 2}, want: nil, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := AsString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("AsString(%T) = (%v, nil), want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AsString(%T) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("AsString(%T) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestAsUint32 exercises AsUint32 across all supported types and edge cases.
func TestAsUint32(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   any
		want    any
		wantErr bool
	}{
		// nil passthrough
		{name: "nil", input: nil, want: nil, wantErr: false},

		// int in range
		{name: "int zero", input: int(0), want: uint32(0), wantErr: false},
		{name: "int positive", input: int(1000), want: uint32(1000), wantErr: false},
		{name: "int max uint32", input: int(math.MaxUint32), want: uint32(math.MaxUint32), wantErr: false},

		// int negative → error
		{name: "int negative", input: int(-1), want: nil, wantErr: true},

		// int64 in range
		{name: "int64 zero", input: int64(0), want: uint32(0), wantErr: false},
		{name: "int64 max uint32", input: int64(math.MaxUint32), want: uint32(math.MaxUint32), wantErr: false},

		// int64 out of range
		{name: "int64 negative", input: int64(-1), want: nil, wantErr: true},
		{name: "int64 overflow", input: int64(1<<32), want: nil, wantErr: true},

		// int32
		{name: "int32 positive", input: int32(255), want: uint32(255), wantErr: false},
		{name: "int32 negative", input: int32(-1), want: nil, wantErr: true},

		// uint32 passthrough
		{name: "uint32 passthrough", input: uint32(42), want: uint32(42), wantErr: false},
		{name: "uint32 max", input: uint32(math.MaxUint32), want: uint32(math.MaxUint32), wantErr: false},

		// uint64 in range and overflow
		{name: "uint64 in range", input: uint64(100), want: uint32(100), wantErr: false},
		{name: "uint64 overflow", input: uint64(1<<32), want: nil, wantErr: true},
		{name: "uint64 max", input: uint64(math.MaxUint64), want: nil, wantErr: true},

		// float64
		{name: "float64 zero", input: float64(0), want: uint32(0), wantErr: false},
		{name: "float64 positive in range", input: float64(65535), want: uint32(65535), wantErr: false},
		{name: "float64 negative", input: float64(-1.0), want: nil, wantErr: true},
		{name: "float64 overflow", input: float64(1 << 33), want: nil, wantErr: true},

		// unsupported type
		{name: "string", input: "123", want: nil, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := AsUint32(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("AsUint32(%T=%v) = (%v, nil), want error", tc.input, tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AsUint32(%T=%v) unexpected error: %v", tc.input, tc.input, err)
			}
			if got != tc.want {
				t.Errorf("AsUint32(%T=%v) = %v, want %v", tc.input, tc.input, got, tc.want)
			}
		})
	}
}

// TestAsUint64 exercises AsUint64 across all supported types and edge cases.
func TestAsUint64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   any
		want    any
		wantErr bool
	}{
		// nil passthrough
		{name: "nil", input: nil, want: nil, wantErr: false},

		// int
		{name: "int zero", input: int(0), want: uint64(0), wantErr: false},
		{name: "int positive", input: int(1<<30), want: uint64(1 << 30), wantErr: false},
		{name: "int negative", input: int(-1), want: nil, wantErr: true},

		// int64
		{name: "int64 zero", input: int64(0), want: uint64(0), wantErr: false},
		{name: "int64 large", input: int64(math.MaxInt64), want: uint64(math.MaxInt64), wantErr: false},
		{name: "int64 negative", input: int64(-1), want: nil, wantErr: true},

		// uint64 passthrough
		{name: "uint64 passthrough", input: uint64(42), want: uint64(42), wantErr: false},
		{name: "uint64 max", input: uint64(math.MaxUint64), want: uint64(math.MaxUint64), wantErr: false},

		// uint32 widening
		{name: "uint32 widening", input: uint32(math.MaxUint32), want: uint64(math.MaxUint32), wantErr: false},
		{name: "uint32 zero", input: uint32(0), want: uint64(0), wantErr: false},

		// float64
		{name: "float64 zero", input: float64(0), want: uint64(0), wantErr: false},
		{name: "float64 positive", input: float64(1000), want: uint64(1000), wantErr: false},
		{name: "float64 negative", input: float64(-0.1), want: nil, wantErr: true},

		// unsupported type
		{name: "string", input: "99", want: nil, wantErr: true},
		{name: "bool", input: true, want: nil, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := AsUint64(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("AsUint64(%T=%v) = (%v, nil), want error", tc.input, tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AsUint64(%T=%v) unexpected error: %v", tc.input, tc.input, err)
			}
			if got != tc.want {
				t.Errorf("AsUint64(%T=%v) = %v, want %v", tc.input, tc.input, got, tc.want)
			}
		})
	}
}
