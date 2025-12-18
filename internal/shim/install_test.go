package shim

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallShellShim_ReplacesAndPreservesReal(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	realShell := filepath.Join(binDir, "sh")
	if err := os.WriteFile(realShell, []byte("REAL_SH\n"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}

	shimPath := filepath.Join(root, "shim.bin")
	if err := os.WriteFile(shimPath, []byte("SHIM\n"), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}

	if err := InstallShellShim(InstallShellShimOptions{Root: root, ShimPath: shimPath}); err != nil {
		t.Fatalf("install: %v", err)
	}

	gotShim, err := os.ReadFile(filepath.Join(binDir, "sh"))
	if err != nil {
		t.Fatalf("read installed sh: %v", err)
	}
	if string(gotShim) != "SHIM\n" {
		t.Fatalf("expected shim content, got %q", string(gotShim))
	}

	gotReal, err := os.ReadFile(filepath.Join(binDir, "sh.real"))
	if err != nil {
		t.Fatalf("read sh.real: %v", err)
	}
	if string(gotReal) != "REAL_SH\n" {
		t.Fatalf("expected real preserved, got %q", string(gotReal))
	}
}

func TestInstallShellShim_Idempotent(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "sh"), []byte("REAL\n"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}
	shimPath := filepath.Join(root, "shim.bin")
	if err := os.WriteFile(shimPath, []byte("SHIM\n"), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}

	if err := InstallShellShim(InstallShellShimOptions{Root: root, ShimPath: shimPath}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := InstallShellShim(InstallShellShimOptions{Root: root, ShimPath: shimPath}); err != nil {
		t.Fatalf("install again: %v", err)
	}

	gotShim, _ := os.ReadFile(filepath.Join(binDir, "sh"))
	gotReal, _ := os.ReadFile(filepath.Join(binDir, "sh.real"))
	if string(gotShim) != "SHIM\n" {
		t.Fatalf("expected shim, got %q", string(gotShim))
	}
	if string(gotReal) != "REAL\n" {
		t.Fatalf("expected real, got %q", string(gotReal))
	}
}

func TestInstallShellShim_SkipsMissingTargets(t *testing.T) {
	root := t.TempDir()
	shimPath := filepath.Join(root, "shim.bin")
	if err := os.WriteFile(shimPath, []byte("SHIM\n"), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	if err := InstallShellShim(InstallShellShimOptions{Root: root, ShimPath: shimPath, InstallBash: true}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "bin", "sh")); err == nil {
		t.Fatalf("expected sh to remain missing")
	}
}

func TestUninstallShellShim_RestoresReal(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "sh"), []byte("REAL\n"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}
	shimPath := filepath.Join(root, "shim.bin")
	if err := os.WriteFile(shimPath, []byte("SHIM\n"), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}

	if err := InstallShellShim(InstallShellShimOptions{Root: root, ShimPath: shimPath}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if err := UninstallShellShim(InstallShellShimOptions{Root: root, InstallBash: false}); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := os.Stat(filepath.Join(binDir, "sh.real")); err == nil {
		t.Fatalf("expected sh.real to be removed after restore")
	}
	got, err := os.ReadFile(filepath.Join(binDir, "sh"))
	if err != nil {
		t.Fatalf("read sh: %v", err)
	}
	if string(got) != "REAL\n" {
		t.Fatalf("expected real restored, got %q", string(got))
	}
}
