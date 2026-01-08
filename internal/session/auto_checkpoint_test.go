package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAutoCheckpoint_ShouldCheckpoint(t *testing.T) {
	tests := []struct {
		name     string
		triggers []string
		command  string
		args     []string
		want     bool
	}{
		{
			name:     "rm triggers",
			triggers: []string{"rm"},
			command:  "rm",
			args:     []string{"-f", "file.txt"},
			want:     true,
		},
		{
			name:     "rm with full path",
			triggers: []string{"rm"},
			command:  "/bin/rm",
			args:     []string{"file.txt"},
			want:     true,
		},
		{
			name:     "mv triggers",
			triggers: []string{"mv"},
			command:  "mv",
			args:     []string{"old.txt", "new.txt"},
			want:     true,
		},
		{
			name:     "git reset triggers",
			triggers: []string{"git reset"},
			command:  "git",
			args:     []string{"reset", "--hard"},
			want:     true,
		},
		{
			name:     "git checkout triggers",
			triggers: []string{"git checkout"},
			command:  "git",
			args:     []string{"checkout", "."},
			want:     true,
		},
		{
			name:     "git status does not trigger",
			triggers: []string{"git reset"},
			command:  "git",
			args:     []string{"status"},
			want:     false,
		},
		{
			name:     "ls does not trigger",
			triggers: []string{"rm", "mv"},
			command:  "ls",
			args:     []string{"-la"},
			want:     false,
		},
		{
			name:     "cat does not trigger",
			triggers: []string{"rm"},
			command:  "cat",
			args:     []string{"file.txt"},
			want:     false,
		},
		{
			name:     "empty triggers",
			triggers: []string{},
			command:  "rm",
			args:     []string{"file.txt"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock manager (not nil)
			storage := NewInMemoryCheckpointStorage()
			manager := NewCheckpointManager(storage)

			ac := NewAutoCheckpoint(AutoCheckpointConfig{
				Enabled:  true,
				Triggers: tt.triggers,
			}, manager)

			got := ac.ShouldCheckpoint(tt.command, tt.args)
			if got != tt.want {
				t.Errorf("ShouldCheckpoint(%q, %v) = %v, want %v", tt.command, tt.args, got, tt.want)
			}
		})
	}
}

func TestAutoCheckpoint_ShouldCheckpoint_Disabled(t *testing.T) {
	storage := NewInMemoryCheckpointStorage()
	manager := NewCheckpointManager(storage)

	ac := NewAutoCheckpoint(AutoCheckpointConfig{
		Enabled:  false,
		Triggers: []string{"rm"},
	}, manager)

	if ac.ShouldCheckpoint("rm", []string{"file.txt"}) {
		t.Error("disabled auto-checkpoint should not trigger")
	}
}

func TestAutoCheckpoint_ShouldCheckpoint_NilManager(t *testing.T) {
	ac := NewAutoCheckpoint(AutoCheckpointConfig{
		Enabled:  true,
		Triggers: []string{"rm"},
	}, nil)

	if ac.ShouldCheckpoint("rm", []string{"file.txt"}) {
		t.Error("nil manager should not trigger")
	}
}

func TestAutoCheckpoint_CreateAutoCheckpoint(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	// Create workspace with file
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "test.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	storage, err := NewFileCheckpointStorage(storageDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}
	manager := NewCheckpointManager(storage)

	ac := NewAutoCheckpoint(AutoCheckpointConfig{
		Enabled:  true,
		Triggers: []string{"rm"},
	}, manager)

	// Create mock session
	sess := &Session{
		ID:        "test-session",
		Workspace: workspace,
	}

	// Should trigger checkpoint
	cpID, err := ac.CreateAutoCheckpoint(sess, "rm", []string{"-f", "test.txt"})
	if err != nil {
		t.Fatalf("CreateAutoCheckpoint: %v", err)
	}
	if cpID == "" {
		t.Error("expected checkpoint ID, got empty")
	}

	// Verify checkpoint was created
	cp, err := manager.GetCheckpoint(sess.ID, cpID)
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if !contains(cp.Reason, "auto:pre_command:rm") {
		t.Errorf("Reason = %q, expected to contain 'auto:pre_command:rm'", cp.Reason)
	}
}

func TestAutoCheckpoint_CreateAutoCheckpoint_NoTrigger(t *testing.T) {
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "checkpoints")
	workspace := filepath.Join(tmpDir, "workspace")

	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("create workspace: %v", err)
	}

	storage, err := NewFileCheckpointStorage(storageDir, 0)
	if err != nil {
		t.Fatalf("NewFileCheckpointStorage: %v", err)
	}
	manager := NewCheckpointManager(storage)

	ac := NewAutoCheckpoint(AutoCheckpointConfig{
		Enabled:  true,
		Triggers: []string{"rm"},
	}, manager)

	sess := &Session{
		ID:        "test-session",
		Workspace: workspace,
	}

	// Should not trigger checkpoint for ls
	cpID, err := ac.CreateAutoCheckpoint(sess, "ls", []string{"-la"})
	if err != nil {
		t.Fatalf("CreateAutoCheckpoint: %v", err)
	}
	if cpID != "" {
		t.Error("expected empty checkpoint ID for non-triggering command")
	}
}

func TestPredictAffectedFiles(t *testing.T) {
	workspace := "/workspace"

	tests := []struct {
		name    string
		command string
		args    []string
		want    []string
	}{
		{
			name:    "rm with files",
			command: "rm",
			args:    []string{"file1.txt", "file2.txt"},
			want:    []string{"file1.txt", "file2.txt"},
		},
		{
			name:    "rm with flags",
			command: "rm",
			args:    []string{"-rf", "dir/"},
			want:    []string{"dir/"},
		},
		{
			name:    "mv source only",
			command: "mv",
			args:    []string{"old.txt", "new.txt"},
			want:    []string{"old.txt"},
		},
		{
			name:    "git reset returns nil for full backup",
			command: "git",
			args:    []string{"reset", "--hard"},
			want:    nil,
		},
		{
			name:    "git checkout specific files",
			command: "git",
			args:    []string{"checkout", "--", "file.txt"},
			want:    []string{"file.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := predictAffectedFiles(workspace, tt.command, tt.args)

			if tt.want == nil {
				if got != nil {
					t.Errorf("predictAffectedFiles = %v, want nil", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("len(predictAffectedFiles) = %d, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("predictAffectedFiles[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDefaultAutoCheckpointTriggers(t *testing.T) {
	triggers := DefaultAutoCheckpointTriggers()
	if len(triggers) == 0 {
		t.Error("expected non-empty default triggers")
	}

	// Check for expected triggers
	expected := map[string]bool{
		"rm":           false,
		"mv":           false,
		"git reset":    false,
		"git checkout": false,
	}

	for _, trigger := range triggers {
		if _, ok := expected[trigger]; ok {
			expected[trigger] = true
		}
	}

	for trigger, found := range expected {
		if !found {
			t.Errorf("expected trigger %q not found in defaults", trigger)
		}
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
