package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestBuiltin_AEnv_ReturnsJSON(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()
	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, _ = s.Builtin(types.ExecRequest{Command: "export", Args: []string{"FOO=bar"}})
	handled, code, out, errOut := s.Builtin(types.ExecRequest{Command: "aenv"})
	if !handled {
		t.Fatalf("expected handled")
	}
	if code != 0 || len(errOut) != 0 {
		t.Fatalf("expected success, code=%d stderr=%q", code, string(errOut))
	}
	var mEnv map[string]string
	if err := json.Unmarshal(out, &mEnv); err != nil {
		t.Fatalf("expected json stdout, got %q: %v", string(out), err)
	}
	if mEnv["FOO"] != "bar" {
		t.Fatalf("expected FOO=bar, got %v", mEnv)
	}
}

func TestBuiltin_ALS_ListsDirectory(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetWorkspaceMount(ws)

	handled, code, out, errOut := s.Builtin(types.ExecRequest{Command: "als"})
	if !handled {
		t.Fatalf("expected handled")
	}
	if code != 0 || len(errOut) != 0 {
		t.Fatalf("expected success, code=%d stderr=%q", code, string(errOut))
	}
	var entries []map[string]any
	if err := json.Unmarshal(out, &entries); err != nil {
		t.Fatalf("expected json stdout, got %q: %v", string(out), err)
	}
	found := false
	for _, e := range entries {
		if e["name"] == "a.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected to find a.txt in %v", entries)
	}
}

func TestBuiltin_AStat_ReturnsMetadata(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()
	p := filepath.Join(ws, "b.bin")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetWorkspaceMount(ws)

	handled, code, out, errOut := s.Builtin(types.ExecRequest{Command: "astat", Args: []string{"/workspace/b.bin"}})
	if !handled {
		t.Fatalf("expected handled")
	}
	if code != 0 || len(errOut) != 0 {
		t.Fatalf("expected success, code=%d stderr=%q", code, string(errOut))
	}
	var st map[string]any
	if err := json.Unmarshal(out, &st); err != nil {
		t.Fatalf("expected json stdout, got %q: %v", string(out), err)
	}
	if st["size_bytes"] != float64(5) {
		t.Fatalf("expected size 5, got %v", st["size_bytes"])
	}
	if st["is_dir"] != false {
		t.Fatalf("expected is_dir false, got %v", st["is_dir"])
	}
	if _, ok := st["mtime"].(string); !ok {
		t.Fatalf("expected mtime string, got %T", st["mtime"])
	}
}

func TestBuiltin_ACat_ReturnsContent(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()
	p := filepath.Join(ws, "c.txt")
	if err := os.WriteFile(p, []byte("content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetWorkspaceMount(ws)

	handled, code, out, errOut := s.Builtin(types.ExecRequest{Command: "acat", Args: []string{"/workspace/c.txt"}})
	if !handled {
		t.Fatalf("expected handled")
	}
	if code != 0 || len(errOut) != 0 {
		t.Fatalf("expected success, code=%d stderr=%q", code, string(errOut))
	}
	var res map[string]any
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("expected json stdout, got %q: %v", string(out), err)
	}
	if res["content"] != "content\n" {
		t.Fatalf("expected content, got %v", res["content"])
	}
	if res["truncated"] != false {
		t.Fatalf("expected truncated false, got %v", res["truncated"])
	}
	if res["size_bytes"] != float64(8) {
		t.Fatalf("expected size 8, got %v", res["size_bytes"])
	}
	if ts, ok := res["mtime"].(string); ok {
		if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			t.Fatalf("expected RFC3339Nano mtime, got %q", ts)
		}
	} else {
		t.Fatalf("expected mtime string, got %T", res["mtime"])
	}
}
