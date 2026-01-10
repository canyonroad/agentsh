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
