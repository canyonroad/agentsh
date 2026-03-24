package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShimConfPath(t *testing.T) {
	tests := []struct {
		root string
		want string
	}{
		{"/", "/etc/agentsh/shim.conf"},
		{"/rootfs", "/rootfs/etc/agentsh/shim.conf"},
		{"", "/etc/agentsh/shim.conf"},
	}
	for _, tt := range tests {
		got := ShimConfPath(tt.root)
		if got != tt.want {
			t.Errorf("ShimConfPath(%q) = %q, want %q", tt.root, got, tt.want)
		}
	}
}

func TestReadShimConf_MissingFile(t *testing.T) {
	root := t.TempDir()
	conf, err := ReadShimConf(root)
	if err != nil {
		t.Fatalf("expected nil error for missing file, got %v", err)
	}
	if conf.Force {
		t.Fatalf("expected Force=false for missing file")
	}
}

func TestReadShimConf_ForceTrue(t *testing.T) {
	root := t.TempDir()
	writeTestConf(t, root, "force=true\n")
	conf, err := ReadShimConf(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !conf.Force {
		t.Fatalf("expected Force=true")
	}
}

func TestReadShimConf_ForceOne(t *testing.T) {
	root := t.TempDir()
	writeTestConf(t, root, "force=1\n")
	conf, err := ReadShimConf(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !conf.Force {
		t.Fatalf("expected Force=true for force=1")
	}
}

func TestReadShimConf_ForceFalse(t *testing.T) {
	root := t.TempDir()
	writeTestConf(t, root, "force=false\n")
	conf, err := ReadShimConf(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conf.Force {
		t.Fatalf("expected Force=false")
	}
}

func TestReadShimConf_CommentsAndBlanks(t *testing.T) {
	root := t.TempDir()
	writeTestConf(t, root, "# comment\n\n  # indented comment\nforce = true\nextra=value\nmalformed line\n")
	conf, err := ReadShimConf(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !conf.Force {
		t.Fatalf("expected Force=true")
	}
	if conf.Raw["extra"] != "value" {
		t.Fatalf("expected Raw[extra]=value, got %q", conf.Raw["extra"])
	}
	// malformed line (no =) should be ignored
	if len(conf.Raw) != 2 {
		t.Fatalf("expected 2 raw keys, got %d: %v", len(conf.Raw), conf.Raw)
	}
}

func TestReadShimConf_InvalidForceValue(t *testing.T) {
	root := t.TempDir()
	writeTestConf(t, root, "force=tru\n")
	conf, err := ReadShimConf(root)
	if err == nil {
		t.Fatalf("expected error for invalid force value 'tru'")
	}
	if conf.Force {
		t.Fatalf("expected Force=false on invalid value")
	}
	if !strings.Contains(err.Error(), "invalid force value") {
		t.Fatalf("expected 'invalid force value' in error, got %q", err.Error())
	}
}

func TestReadShimConf_Unreadable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root")
	}
	root := t.TempDir()
	confDir := filepath.Join(root, "etc", "agentsh")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(confDir, "shim.conf")
	if err := os.WriteFile(confPath, []byte("force=true\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	conf, err := ReadShimConf(root)
	if err == nil {
		t.Fatalf("expected error for unreadable file")
	}
	if conf.Force {
		t.Fatalf("expected Force=false on read error")
	}
	if len(conf.Raw) != 0 {
		t.Fatalf("expected empty Raw on read error, got %v", conf.Raw)
	}
}

func TestWriteShimConf_CreatesDirectoryAndFile(t *testing.T) {
	root := t.TempDir()
	conf := ShimConf{
		Force: true,
		Raw:   map[string]string{"force": "true"},
	}
	if err := WriteShimConf(root, conf); err != nil {
		t.Fatalf("WriteShimConf: %v", err)
	}

	// Check directory permissions.
	dirInfo, err := os.Stat(filepath.Join(root, "etc", "agentsh"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o755 {
		t.Fatalf("expected dir perm 0o755, got %o", perm)
	}

	// Check file permissions.
	fileInfo, err := os.Stat(ShimConfPath(root))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o644 {
		t.Fatalf("expected file perm 0o644, got %o", perm)
	}

	// Check content contains force=true.
	data, err := os.ReadFile(ShimConfPath(root))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "force=true") {
		t.Fatalf("expected force=true in content, got %q", string(data))
	}

	// Check header comment.
	if !strings.Contains(string(data), "# Written by: agentsh shim install-shell") {
		t.Fatalf("expected header in content, got %q", string(data))
	}
}

func TestWriteShimConf_RoundTrip(t *testing.T) {
	root := t.TempDir()
	original := ShimConf{
		Force: true,
		Raw:   map[string]string{"force": "true", "debug": "1"},
	}
	if err := WriteShimConf(root, original); err != nil {
		t.Fatalf("WriteShimConf: %v", err)
	}
	got, err := ReadShimConf(root)
	if err != nil {
		t.Fatalf("ReadShimConf: %v", err)
	}
	if !got.Force {
		t.Fatalf("expected Force=true after round-trip")
	}
	if got.Raw["debug"] != "1" {
		t.Fatalf("expected Raw[debug]=1, got %q", got.Raw["debug"])
	}

	// Check that keys are written in alphabetical order (debug before force).
	raw, err := os.ReadFile(ShimConfPath(root))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	debugIdx := strings.Index(string(raw), "debug=")
	forceIdx := strings.Index(string(raw), "force=")
	if debugIdx < 0 || forceIdx < 0 {
		t.Fatalf("expected both debug= and force= in file, got %q", string(raw))
	}
	if debugIdx > forceIdx {
		t.Fatalf("expected debug= before force= (alphabetical order), got:\n%s", string(raw))
	}
}

// writeTestConf writes content to {root}/etc/agentsh/shim.conf.
func writeTestConf(t *testing.T, root, content string) {
	t.Helper()
	dir := filepath.Join(root, "etc", "agentsh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shim.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
