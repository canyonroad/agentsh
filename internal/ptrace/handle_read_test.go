//go:build linux

package ptrace

import (
	"bytes"
	"testing"
)

func TestMaskTracerPid(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "typical /proc/self/status",
			input:  "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12345\nNgid:\t0\nPid:\t12345\nPPid:\t1\nTracerPid:\t67890\nUid:\t1000\t1000\t1000\t1000\n",
			expect: "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12345\nNgid:\t0\nPid:\t12345\nPPid:\t1\nTracerPid:\t0    \nUid:\t1000\t1000\t1000\t1000\n",
		},
		{
			name:   "TracerPid is zero (not traced)",
			input:  "TracerPid:\t0\nUid:\t1000\n",
			expect: "TracerPid:\t0\nUid:\t1000\n",
		},
		{
			name:   "no TracerPid line",
			input:  "Name:\tsleep\nPid:\t1234\n",
			expect: "Name:\tsleep\nPid:\t1234\n",
		},
		{
			name:   "TracerPid at end without newline",
			input:  "TracerPid:\t999",
			expect: "TracerPid:\t0  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := []byte(tt.input)
			maskTracerPid(buf)
			if !bytes.Equal(buf, []byte(tt.expect)) {
				t.Errorf("expected %q, got %q", tt.expect, string(buf))
			}
		})
	}
}
