package shim

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type InstallShellShimOptions struct {
	// Root is the root filesystem directory to operate under.
	// For the real host filesystem, pass "/".
	Root string

	// ShimPath is the path to the agentsh shell shim binary to install.
	ShimPath string

	// InstallBash controls whether to also install to bash when present.
	InstallBash bool
}

// InstallShellShim installs the agentsh shell shim as /bin/sh (and optionally /bin/bash)
// under opts.Root, preserving the original binaries as *.real.
//
// This function is intended for container build/install scripts; it is idempotent.
func InstallShellShim(opts InstallShellShimOptions) error {
	root := filepath.Clean(opts.Root)
	if root == "" {
		root = "/"
	}
	if opts.ShimPath == "" {
		return fmt.Errorf("shim path is required")
	}
	shimBytes, err := os.ReadFile(opts.ShimPath)
	if err != nil {
		return fmt.Errorf("read shim: %w", err)
	}

	if err := installOne(root, "sh", shimBytes); err != nil {
		return err
	}
	if opts.InstallBash {
		if err := installOne(root, "bash", shimBytes); err != nil {
			return err
		}
	}
	return nil
}

// UninstallShellShim restores /bin/sh.real -> /bin/sh (and optionally bash) under opts.Root.
func UninstallShellShim(opts InstallShellShimOptions) error {
	root := filepath.Clean(opts.Root)
	if root == "" {
		root = "/"
	}
	if err := uninstallOne(root, "sh"); err != nil {
		return err
	}
	if opts.InstallBash {
		if err := uninstallOne(root, "bash"); err != nil {
			return err
		}
	}
	return nil
}

func installOne(root, shellName string, shimBytes []byte) error {
	target := filepath.Join(root, "bin", shellName)
	real := target + ".real"

	// If target is missing, treat as "not present" and skip.
	if _, err := os.Lstat(target); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", target, err)
	}

	// Ensure *.real exists. If missing, rename target -> *.real unless target already matches shim.
	if _, err := os.Lstat(real); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", real, err)
		}
		if sameFileContents(target, shimBytes) {
			// Already shimmed but missing .real; don't destroy the shim.
			return nil
		}
		if err := os.Rename(target, real); err != nil {
			return fmt.Errorf("rename %s -> %s: %w", target, real, err)
		}
	}

	return writeFileAtomic(target, shimBytes, 0o755)
}

func uninstallOne(root, shellName string) error {
	target := filepath.Join(root, "bin", shellName)
	real := target + ".real"

	if _, err := os.Lstat(real); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", real, err)
	}

	// Restore real over target (best-effort remove of current target first).
	_ = os.Remove(target)
	if err := os.Rename(real, target); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", real, target, err)
	}
	return nil
}

func sameFileContents(path string, want []byte) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	got, err := io.ReadAll(io.LimitReader(f, int64(len(want)+1)))
	if err != nil {
		return false
	}
	return bytes.Equal(got, want)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp -> %s: %w", path, err)
	}
	return nil
}
