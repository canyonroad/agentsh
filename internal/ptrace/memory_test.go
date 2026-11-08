//go:build linux

package ptrace

import (
	"fmt"
	"testing"
)

type mockMemReader struct {
	data []byte
}

func (m *mockMemReader) read(addr uint64, buf []byte) error {
	start := int(addr)
	if start >= len(m.data) {
		return fmt.Errorf("read past end")
	}
	end := start + len(buf)
	if end > len(m.data) {
		end = len(m.data)
	}
	copy(buf, m.data[start:end])
	for i := end - start; i < len(buf); i++ {
		buf[i] = 0
	}
	return nil
}

func TestReadStringFromBuffer(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		maxLen int
		want   string
	}{
		{
			name:   "simple",
			data:   []byte("hello\x00world"),
			maxLen: 100,
			want:   "hello",
		},
		{
			name:   "max length truncation",
			data:   []byte("abcdefgh\x00"),
			maxLen: 5,
			want:   "abcde",
		},
		{
			name:   "empty string",
			data:   []byte("\x00rest"),
			maxLen: 100,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &mockMemReader{data: tt.data}
			got, err := readStringFrom(reader, 0, tt.maxLen)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("readString = %q, want %q", got, tt.want)
			}
		})
	}
}

// buildArgv lays out a pointer array followed by NUL-terminated strings, the way
// a real argv block looks: argvPtr -> [ptr0, ptr1, ..., NULL], strings above.
func buildArgv(args []string) ([]byte, uint64) {
	const base = 0x1000
	count := len(args) + 1
	ptrs := make([]byte, count*8)
	data := make([]byte, 0, 4096)
	strStart := base + count*8
	for i, a := range args {
		addr := uint64(strStart + len(data))
		for b := 0; b < 8; b++ {
			ptrs[i*8+b] = byte(addr >> (8 * b))
		}
		data = append(data, a...)
		data = append(data, 0)
	}
	buf := make([]byte, strStart-base+len(data))
	copy(buf, ptrs)
	copy(buf[count*8:], data)
	return buf, base
}

func TestReadArgv_Boundaries(t *testing.T) {
	long := make([]byte, maxArgLen+10)
	for i := range long {
		long[i] = 'a'
	}
	tests := []struct {
		name          string
		args          []string
		maxArgc       int
		wantLen       int
		wantTruncated bool
	}{
		{name: "exactly maxArgc terminated", args: []string{"a", "b", "c"}, maxArgc: 3, wantLen: 3, wantTruncated: false},
		{name: "one past maxArgc", args: []string{"a", "b", "c", "d"}, maxArgc: 3, wantLen: 3, wantTruncated: true},
		{name: "overlong element", args: []string{"a", string(long)}, maxArgc: 10, wantLen: 2, wantTruncated: true},
		{name: "empty argv", args: nil, maxArgc: 10, wantLen: 0, wantTruncated: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf, argvPtr := buildArgv(tt.args)
			// readArgv indexes from argvPtr, so shift the reader by making the
			// buffer start at argvPtr.
			shifted := &offsetMemReader{inner: &mockMemReader{data: buf}, off: argvPtr}
			args, truncated, err := readArgvFrom(shifted, argvPtr, tt.maxArgc, 1<<20)
			if err != nil {
				t.Fatalf("readArgv: %v", err)
			}
			if len(args) != tt.wantLen {
				t.Fatalf("args = %d, want %d", len(args), tt.wantLen)
			}
			if truncated != tt.wantTruncated {
				t.Fatalf("truncated = %v, want %v", truncated, tt.wantTruncated)
			}
		})
	}
}

type offsetMemReader struct {
	inner *mockMemReader
	off   uint64
}

func (o *offsetMemReader) read(addr uint64, buf []byte) error {
	return o.inner.read(addr-o.off, buf)
}
