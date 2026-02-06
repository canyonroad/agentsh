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

		// If target is a symlink (e.g. /bin/sh -> /bin/bash on Fedora/Arch),
		// resolve it and copy the real binary instead of renaming the symlink.
		// A renamed symlink would point to the shim after bash gets shimmed,
		// causing an infinite exec loop in the recursion guard.
		if linkTarget, err := os.Readlink(target); err == nil {
			// It's a symlink. Resolve to the absolute path of the real binary.
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(target), linkTarget)
			}
			resolved, err := filepath.EvalSymlinks(linkTarget)
			if err != nil {
				return fmt.Errorf("resolve symlink %s -> %s: %w", target, linkTarget, err)
			}
			// Copy the resolved binary to *.real instead of renaming the symlink.
			if err := copyFile(resolved, real); err != nil {
				return fmt.Errorf("copy %s -> %s: %w", resolved, real, err)
			}
			// Remove the original symlink so we can write the shim in its place.
			if err := os.Remove(target); err != nil {
				return fmt.Errorf("remove symlink %s: %w", target, err)
			}
		} else {
			// Not a symlink, rename as before.
			if err := os.Rename(target, real); err != nil {
				return fmt.Errorf("rename %s -> %s: %w", target, real, err)
			}
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

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
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
