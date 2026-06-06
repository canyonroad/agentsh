package wrapperlog

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenStateLogFile_CreatesDirAndAppends(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_STATE_HOME redirection is linux-only")
	}
	stateHome := t.TempDir()
	t.Setenv("XDG_STATE_HOME", stateHome)

	f, err := OpenStateLogFile()
	if err != nil {
		t.Fatalf("OpenStateLogFile: %v", err)
	}
	if _, err := f.WriteString("first\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	// A second open must append, not truncate.
	f2, err := OpenStateLogFile()
	if err != nil {
		t.Fatalf("OpenStateLogFile (second): %v", err)
	}
	if _, err := f2.WriteString("second\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f2.Close()

	got, err := os.ReadFile(filepath.Join(stateHome, "agentsh", "logs", "unixwrap.log"))
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(got) != "first\nsecond\n" {
		t.Fatalf("log content = %q, want %q", got, "first\nsecond\n")
	}
}

func TestEnvKey_Value(t *testing.T) {
	// The wrapper and all three parents must agree on this string;
	// pin it so a rename can't silently desynchronize them.
	if EnvKey != "AGENTSH_WRAPPER_LOG_FD" {
		t.Fatalf("EnvKey = %q", EnvKey)
	}
}
