// internal/netmonitor/unix/execve_handler_test.go
package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecveHandler_InternalBypass(t *testing.T) {
	cfg := ExecveHandlerConfig{
		InternalBypass: []string{
			"/usr/local/bin/agentsh",
			"/usr/local/bin/agentsh-*",
			"*.real",
		},
	}
	h := NewExecveHandler(cfg, nil, nil, nil)

	tests := []struct {
		filename string
		bypass   bool
	}{
		{"/usr/local/bin/agentsh", true},
		{"/usr/local/bin/agentsh-unixwrap", true},
		{"/bin/bash.real", true},
		{"/usr/bin/sh.real", true},
		{"/usr/bin/git", false},
		{"/bin/bash", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.bypass, h.isInternalBypass(tt.filename))
		})
	}
}
