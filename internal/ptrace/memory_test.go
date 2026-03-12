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
