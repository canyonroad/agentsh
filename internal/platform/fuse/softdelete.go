// internal/platform/fuse/softdelete.go
//go:build cgo

package fuse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	cgofuse "github.com/winfsp/cgofuse/fuse"
)

// softDelete moves a file to trash instead of deleting.
func (f *fuseFS) softDelete(realPath, virtPath string) int {
	if f.cfg.TrashConfig == nil || !f.cfg.TrashConfig.Enabled {
		return -cgofuse.EACCES
	}

	// Generate unique trash path
	trashPath := f.trashPath(realPath)

	// Validate trash path stays within trash directory
	absTrash, err := filepath.Abs(f.cfg.TrashConfig.TrashDir)
	if err != nil {
		return toErrno(err)
	}
	absPath, err := filepath.Abs(trashPath)
	if err != nil {
		return toErrno(err)
	}
	if !strings.HasPrefix(absPath, absTrash) {
		return -cgofuse.EACCES
	}

	// Ensure trash directory exists
	trashDir := filepath.Dir(trashPath)
	if err := os.MkdirAll(trashDir, 0755); err != nil {
		return toErrno(err)
	}

	// Optionally hash file before moving
	var hash string
	if f.cfg.TrashConfig.HashFiles {
		var err error
		hash, err = f.hashFile(realPath)
		if err != nil {
			// Log error but continue with soft-delete
			hash = ""
		}
	}

	// Move to trash
	if err := os.Rename(realPath, trashPath); err != nil {
		return toErrno(err)
	}

	// Generate restore token
	token := f.generateRestoreToken(virtPath, trashPath, hash)

	// Notify callback
	if f.cfg.NotifySoftDelete != nil {
		f.cfg.NotifySoftDelete(virtPath, token)
	}

	f.emitEvent("file_soft_delete", virtPath, platform.FileOpDelete, platform.DecisionAllow, false)
	return 0
}

// trashPath generates a unique path in the trash directory.
func (f *fuseFS) trashPath(realPath string) string {
	baseName := filepath.Base(realPath)
	timestamp := time.Now().UnixNano()
	trashName := fmt.Sprintf("%s.%d", baseName, timestamp)
	return filepath.Join(f.cfg.TrashConfig.TrashDir, trashName)
}

// hashFile computes the SHA256 hash of a file.
func (f *fuseFS) hashFile(path string) (string, error) {
	// Check file size limit
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if f.cfg.TrashConfig.HashLimitBytes > 0 && info.Size() > f.cfg.TrashConfig.HashLimitBytes {
		return "", nil // Skip hashing large files
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// generateRestoreToken creates a token for restoring a soft-deleted file.
func (f *fuseFS) generateRestoreToken(virtPath, trashPath, hash string) string {
	// Simple token format: base64 of JSON or similar
	// For now, just return the trash path as the token
	return trashPath
}
