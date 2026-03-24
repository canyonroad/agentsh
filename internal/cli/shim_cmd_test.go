package cli

import (
	"bytes"
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

func TestShimInstallShell_BashOnly(t *testing.T) {
	tmp := t.TempDir()
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Create both sh and bash in the fake rootfs.
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "sh"), []byte("REAL_SH\n"), 0o755); err != nil {
		t.Fatalf("write sh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "bash"), []byte("REAL_BASH\n"), 0o755); err != nil {
		t.Fatalf("write bash: %v", err)
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
		"--bash-only",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// /bin/bash should be shimmed (bash.real created, bash replaced with shim).
	if _, err := os.Stat(filepath.Join(rootfs, "bin", "bash.real")); err != nil {
		t.Fatalf("expected bash.real to exist: %v", err)
	}
	bashContent, _ := os.ReadFile(filepath.Join(rootfs, "bin", "bash"))
	if string(bashContent) != "SHIM\n" {
		t.Fatalf("expected bash to be shimmed, got %q", bashContent)
	}

	// /bin/sh should NOT be touched.
	if _, err := os.Stat(filepath.Join(rootfs, "bin", "sh.real")); err == nil {
		t.Fatalf("sh.real should NOT exist when --bash-only is used")
	}
	shContent, _ := os.ReadFile(filepath.Join(rootfs, "bin", "sh"))
	if string(shContent) != "REAL_SH\n" {
		t.Fatalf("sh should be untouched, got %q", shContent)
	}
}

func TestShimInstallShell_BashOnlyAndBash_MutuallyExclusive(t *testing.T) {
	root := NewRoot("test")
	root.SetArgs([]string{
		"shim", "install-shell",
		"--root", "/nonexistent",
		"--shim", "/nonexistent/shim",
		"--bash",
		"--bash-only",
	})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatalf("expected error when both --bash and --bash-only are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got %q", err.Error())
	}
}

func TestShimInstallShell_ForceWritesConfig(t *testing.T) {
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
		"--force",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	confPath := filepath.Join(rootfs, "etc", "agentsh", "shim.conf")
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("expected shim.conf to exist: %v", err)
	}
	if !strings.Contains(string(data), "force=true") {
		t.Fatalf("expected force=true in shim.conf, got %q", string(data))
	}
}

func TestShimInstallShell_NoForceNoConfig(t *testing.T) {
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

	confPath := filepath.Join(rootfs, "etc", "agentsh", "shim.conf")
	if _, err := os.Stat(confPath); err == nil {
		t.Fatalf("expected shim.conf NOT to exist without --force")
	}
}

func TestShimInstallShell_ForceDryRun(t *testing.T) {
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
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{
		"shim", "install-shell",
		"--root", rootfs,
		"--shim", shimPath,
		"--force",
		"--dry-run",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// Dry run should NOT write the file.
	confPath := filepath.Join(rootfs, "etc", "agentsh", "shim.conf")
	if _, err := os.Stat(confPath); err == nil {
		t.Fatalf("dry-run should NOT write shim.conf")
	}

	// Dry run output should mention the config file path.
	if !strings.Contains(stdout.String(), "shim.conf") {
		t.Fatalf("expected dry-run output to mention shim.conf, got %q", stdout.String())
	}
}

func TestShimInstallShell_ReinstallWithoutForceClearsConfig(t *testing.T) {
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

	// First install with --force.
	root := NewRoot("test")
	root.SetArgs([]string{
		"shim", "install-shell",
		"--root", rootfs,
		"--shim", shimPath,
		"--force",
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("first install: %v", err)
	}

	confPath := filepath.Join(rootfs, "etc", "agentsh", "shim.conf")
	data, _ := os.ReadFile(confPath)
	if !strings.Contains(string(data), "force=true") {
		t.Fatalf("expected force=true after --force install, got %q", string(data))
	}

	// Reinstall WITHOUT --force. Should clear force=true.
	root2 := NewRoot("test")
	root2.SetArgs([]string{
		"shim", "install-shell",
		"--root", rootfs,
		"--shim", shimPath,
	})
	if err := root2.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("second install: %v", err)
	}

	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("expected shim.conf to still exist: %v", err)
	}
	if strings.Contains(string(data), "force=true") {
		t.Fatalf("expected force=true to be cleared after reinstall without --force, got %q", string(data))
	}
	if !strings.Contains(string(data), "force=false") {
		t.Fatalf("expected force=false in shim.conf, got %q", string(data))
	}
}
