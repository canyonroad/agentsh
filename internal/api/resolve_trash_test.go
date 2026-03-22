package api

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveTrashPath(t *testing.T) {
	// Use platform-appropriate absolute paths so tests pass on all OSes.
	var absWorkspace, absTrash string
	if runtime.GOOS == "windows" {
		absWorkspace = `C:\Users\user\project`
		absTrash = `C:\tmp\trash`
	} else {
		absWorkspace = "/home/user/project"
		absTrash = "/tmp/trash"
	}

	tests := []struct {
		name      string
		trashPath string
		workspace string
		want      string
	}{
		{
			name:      "empty defaults to .agentsh_trash relative to workspace",
			trashPath: "",
			workspace: absWorkspace,
			want:      filepath.Join(absWorkspace, ".agentsh_trash"),
		},
		{
			name:      "absolute path returned as-is",
			trashPath: absTrash,
			workspace: absWorkspace,
			want:      absTrash,
		},
		{
			name:      "relative path resolved against workspace",
			trashPath: ".my_trash",
			workspace: absWorkspace,
			want:      filepath.Join(absWorkspace, ".my_trash"),
		},
		{
			name:      "nested relative path resolved against workspace",
			trashPath: filepath.Join(".agentsh", "trash"),
			workspace: absWorkspace,
			want:      filepath.Join(absWorkspace, ".agentsh", "trash"),
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
			trashPath: absTrash,
			workspace: "",
			want:      absTrash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTrashPath(tt.trashPath, tt.workspace)
			// For non-empty expected results, normalize via filepath.Abs for comparison.
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
