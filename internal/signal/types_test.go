//go:build !windows

// internal/signal/types_test.go
package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestSignalFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
		wantErr  bool
	}{
		{"SIGKILL", int(unix.SIGKILL), false},
		{"SIGTERM", int(unix.SIGTERM), false},
		{"9", 9, false},
		{"15", 15, false},
		{"INVALID", 0, true},
		// Shorthand without SIG prefix
		{"TERM", int(unix.SIGTERM), false},
		{"KILL", int(unix.SIGKILL), false},
		{"HUP", int(unix.SIGHUP), false},
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
		{"@fatal", []int{int(unix.SIGKILL), int(unix.SIGTERM), int(unix.SIGQUIT), int(unix.SIGABRT)}, false},
		{"@job", []int{int(unix.SIGSTOP), int(unix.SIGCONT), int(unix.SIGTSTP), int(unix.SIGTTIN), int(unix.SIGTTOU)}, false},
		{"@all", AllSignals(), false},
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

func TestSignalName(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{int(unix.SIGKILL), "SIGKILL"},
		{int(unix.SIGTERM), "SIGTERM"},
		{int(unix.SIGHUP), "SIGHUP"},
		{int(unix.SIGINT), "SIGINT"},
		// Unknown signal should return SIG<number>
		{99, "SIG99"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := SignalName(tt.input)
			assert.Equal(t, tt.expected, name)
		})
	}
}

func TestIsSignalGroup(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"@fatal", true},
		{"@job", true},
		{"@reload", true},
		{"  @fatal", true}, // with leading whitespace
		{"SIGKILL", false},
		{"fatal", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsSignalGroup(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAllSignals(t *testing.T) {
	signals := AllSignals()

	// Should return 31 signals (standard Unix signals 1-31)
	assert.Len(t, signals, 31)

	// Verify the range is correct
	assert.Equal(t, 1, signals[0])
	assert.Equal(t, 31, signals[30])

	// Verify sequential order
	for i, sig := range signals {
		assert.Equal(t, i+1, sig)
	}
}
