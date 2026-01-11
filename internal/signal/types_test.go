// internal/signal/types_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignalFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"SIGKILL", 9, false},
		{"SIGTERM", 15, false},
		{"9", 9, false},
		{"15", 15, false},
		{"INVALID", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			sig, err := SignalFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, sig)
			}
		})
	}
}

func TestExpandSignalGroup(t *testing.T) {
	tests := []struct {
		group    string
		expected []int
		wantErr  bool
	}{
		{"@fatal", []int{9, 15, 3, 6}, false},      // SIGKILL, SIGTERM, SIGQUIT, SIGABRT
		{"@job", []int{19, 18, 20, 21, 22}, false}, // SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU
		{"@invalid", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			signals, err := ExpandSignalGroup(tt.group)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tt.expected, signals)
			}
		})
	}
}
