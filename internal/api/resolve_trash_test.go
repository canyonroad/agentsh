package api

import (
	"path/filepath"
	"testing"
)

func TestResolveTrashPath(t *testing.T) {
	tests := []struct {
		name      string
		trashPath string
		workspace string
		want      string
	}{
		{
			name:      "empty defaults to .agentsh_trash relative to workspace",
			trashPath: "",
			workspace: "/home/user/project",
			want:      "/home/user/project/.agentsh_trash",
		},
		{
			name:      "absolute path returned as-is",
			trashPath: "/tmp/trash",
			workspace: "/home/user/project",
			want:      "/tmp/trash",
		},
		{
			name:      "relative path resolved against workspace",
			trashPath: ".my_trash",
			workspace: "/home/user/project",
			want:      "/home/user/project/.my_trash",
		},
		{
			name:      "nested relative path resolved against workspace",
			trashPath: ".agentsh/trash",
			workspace: "/home/user/project",
			want:      "/home/user/project/.agentsh/trash",
		},
		{
			name:      "empty workspace with relative path returns empty",
			trashPath: ".agentsh_trash",
			workspace: "",
			want:      "",
		},
		{
			name:      "empty workspace with default returns empty",
			trashPath: "",
			workspace: "",
			want:      "",
		},
		{
			name:      "absolute path with empty workspace still works",
			trashPath: "/tmp/trash",
			workspace: "",
			want:      "/tmp/trash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTrashPath(tt.trashPath, tt.workspace)
			// For non-empty results with relative input, compare cleaned absolute paths.
			if tt.want != "" {
				want, _ := filepath.Abs(tt.want)
				if got != want {
					t.Errorf("resolveTrashPath(%q, %q) = %q, want %q", tt.trashPath, tt.workspace, got, want)
				}
			} else if got != tt.want {
				t.Errorf("resolveTrashPath(%q, %q) = %q, want %q", tt.trashPath, tt.workspace, got, tt.want)
			}
		})
	}
}
