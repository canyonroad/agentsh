package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandVariables_Simple(t *testing.T) {
	vars := map[string]string{
		"PROJECT_ROOT": "/home/user/myproject",
		"HOME":         "/home/user",
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "simple variable",
			input: "${PROJECT_ROOT}/src",
			want:  "/home/user/myproject/src",
		},
		{
			name:  "multiple variables",
			input: "${HOME}/.config/${PROJECT_ROOT}",
			want:  "/home/user/.config//home/user/myproject",
		},
		{
			name:  "no variables",
			input: "/tmp/foo/bar",
			want:  "/tmp/foo/bar",
		},
		{
			name:  "variable at end",
			input: "/prefix/${PROJECT_ROOT}",
			want:  "/prefix//home/user/myproject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandVariables(tt.input, vars)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExpandVariables_Fallback(t *testing.T) {
	vars := map[string]string{
		"PROJECT_ROOT": "/home/user/myproject",
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "fallback not used when var exists",
			input: "${PROJECT_ROOT:-/fallback}",
			want:  "/home/user/myproject",
		},
		{
			name:  "fallback used when var missing",
			input: "${UNDEFINED:-/fallback}",
			want:  "/fallback",
		},
		{
			name:  "empty fallback",
			input: "${UNDEFINED:-}",
			want:  "",
		},
		{
			name:  "fallback with path",
			input: "${GIT_ROOT:-${PROJECT_ROOT}}/config",
			want:  "${PROJECT_ROOT}/config", // nested not expanded
		},
		{
			name:    "undefined without fallback errors",
			input:   "${UNDEFINED}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandVariables(tt.input, vars)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "undefined variable")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
