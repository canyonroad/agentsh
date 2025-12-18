package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShimInstallShell_RefusesHostRootByDefault(t *testing.T) {
	root := NewRoot("test")
	root.SetArgs([]string{
		"shim", "install-shell",
		"--root", "/",
		"--shim", "/nonexistent/shim",
	})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := err.Error(); got == "" || got == "exit 0" {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "refusing to modify host rootfs"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q in error, got %q", want, err.Error())
	}
}

func TestShimUninstallShell_RefusesHostRootByDefault(t *testing.T) {
	root := NewRoot("test")
	root.SetArgs([]string{
		"shim", "uninstall-shell",
		"--root", "/",
	})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if want := "refusing to modify host rootfs"; !strings.Contains(err.Error(), want) {
		t.Fatalf("expected %q in error, got %q", want, err.Error())
	}
}

func TestShimInstallShell_AllowsNonRootfs(t *testing.T) {
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "sh"), []byte("REAL\n"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}
	shimPath := filepath.Join(tmp, "shim.bin")
	if err := os.WriteFile(shimPath, []byte("SHIM\n"), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}

	root := NewRoot("test")
	root.SetArgs([]string{
		"shim", "install-shell",
		"--root", rootfs,
		"--shim", shimPath,
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootfs, "bin", "sh.real")); err != nil {
		t.Fatalf("expected sh.real to exist: %v", err)
	}
}
