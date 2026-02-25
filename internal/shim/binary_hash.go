package shim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// HashBinary computes SHA-256 of the binary at the given path.
// If path is not absolute, resolves via exec.LookPath.
func HashBinary(path string) (absPath string, hash string, err error) {
	if filepath.IsAbs(path) {
		absPath = path
	} else {
		absPath, err = exec.LookPath(path)
		if err != nil {
			return "", "", fmt.Errorf("resolve binary path: %w", err)
		}
	}
	f, err := os.Open(absPath)
	if err != nil {
		return absPath, "", fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return absPath, "", fmt.Errorf("hash binary: %w", err)
	}
	return absPath, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
