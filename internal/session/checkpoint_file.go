package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrRollbackFailed = errors.New("rollback failed")
	ErrFileTooLarge   = errors.New("file too large for checkpoint")
)

// FileEntry describes a file stored in a checkpoint.
type FileEntry struct {
	Path string      `json:"path"` // Relative path within workspace
	Hash string      `json:"hash"` // SHA-256 hash of content
	Size int64       `json:"size"`
	Mode os.FileMode `json:"mode"`
}

// CheckpointMetadata extends Checkpoint with file-level detail.
type CheckpointMetadata struct {
	Checkpoint
	Files []FileEntry `json:"files"`
}

// FileDiff describes a difference between checkpoint and current workspace.
type FileDiff struct {
	Path    string `json:"path"`
	Status  string `json:"status"` // "added", "modified", "deleted"
	OldHash string `json:"old_hash,omitempty"`
	NewHash string `json:"new_hash,omitempty"`
	OldSize int64  `json:"old_size,omitempty"`
	NewSize int64  `json:"new_size,omitempty"`
}

// FileCheckpointStorage provides persistent checkpoint storage with file backup.
type FileCheckpointStorage struct {
	mu         sync.RWMutex
	baseDir    string
	maxSizeMB  int   // Max size per checkpoint (0 = unlimited)
	maxFileMB  int64 // Max individual file size (default 100MB)
}

// NewFileCheckpointStorage creates a new file-based checkpoint storage.
func NewFileCheckpointStorage(baseDir string, maxSizeMB int) (*FileCheckpointStorage, error) {
	if baseDir == "" {
		return nil, errors.New("checkpoint storage base dir required")
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("create checkpoint dir: %w", err)
	}
	return &FileCheckpointStorage{
		baseDir:   baseDir,
		maxSizeMB: maxSizeMB,
		maxFileMB: 100, // 100MB default max file size
	}, nil
}

// sessionDir returns the directory for a session's checkpoints.
func (s *FileCheckpointStorage) sessionDir(sessionID string) string {
	return filepath.Join(s.baseDir, sessionID)
}

// checkpointDir returns the directory for a specific checkpoint.
func (s *FileCheckpointStorage) checkpointDir(sessionID, checkpointID string) string {
	return filepath.Join(s.sessionDir(sessionID), checkpointID)
}

// metadataPath returns the path to the checkpoint metadata file.
func (s *FileCheckpointStorage) metadataPath(sessionID, checkpointID string) string {
	return filepath.Join(s.checkpointDir(sessionID, checkpointID), "metadata.json")
}

// filesDir returns the directory for checkpoint file contents.
func (s *FileCheckpointStorage) filesDir(sessionID, checkpointID string) string {
	return filepath.Join(s.checkpointDir(sessionID, checkpointID), "files")
}

// Save stores a checkpoint's metadata.
func (s *FileCheckpointStorage) Save(cp *Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cpDir := s.checkpointDir(cp.SessionID, cp.ID)
	if err := os.MkdirAll(cpDir, 0755); err != nil {
		return fmt.Errorf("create checkpoint dir: %w", err)
	}

	meta := CheckpointMetadata{Checkpoint: *cp}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	metaPath := s.metadataPath(cp.SessionID, cp.ID)
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

// Load retrieves a checkpoint's metadata.
func (s *FileCheckpointStorage) Load(sessionID, checkpointID string) (*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metaPath := s.metadataPath(sessionID, checkpointID)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var meta CheckpointMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return &meta.Checkpoint, nil
}

// LoadMetadata retrieves full checkpoint metadata including file list.
func (s *FileCheckpointStorage) LoadMetadata(sessionID, checkpointID string) (*CheckpointMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metaPath := s.metadataPath(sessionID, checkpointID)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var meta CheckpointMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return &meta, nil
}

// List returns all checkpoints for a session, sorted by creation time.
func (s *FileCheckpointStorage) List(sessionID string) ([]*Checkpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessDir := s.sessionDir(sessionID)
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read session dir: %w", err)
	}

	var checkpoints []*Checkpoint
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := s.metadataPath(sessionID, entry.Name())
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue // Skip invalid checkpoints
		}
		var meta CheckpointMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		checkpoints = append(checkpoints, &meta.Checkpoint)
	}

	// Sort by creation time (oldest first)
	sort.Slice(checkpoints, func(i, j int) bool {
		return checkpoints[i].CreatedAt.Before(checkpoints[j].CreatedAt)
	})

	return checkpoints, nil
}

// Delete removes a checkpoint and its files.
func (s *FileCheckpointStorage) Delete(sessionID, checkpointID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cpDir := s.checkpointDir(sessionID, checkpointID)
	if err := os.RemoveAll(cpDir); err != nil {
		return fmt.Errorf("remove checkpoint: %w", err)
	}

	// Clean up empty session dir
	sessDir := s.sessionDir(sessionID)
	entries, _ := os.ReadDir(sessDir)
	if len(entries) == 0 {
		_ = os.Remove(sessDir)
	}

	return nil
}

// CreateSnapshot backs up specified files to checkpoint storage.
// If files is nil, backs up the entire workspace.
func (s *FileCheckpointStorage) CreateSnapshot(sessionID, checkpointID string, files []string, workspacePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cpDir := s.checkpointDir(sessionID, checkpointID)
	filesDir := s.filesDir(sessionID, checkpointID)

	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return fmt.Errorf("create files dir: %w", err)
	}

	var fileEntries []FileEntry
	var totalSize int64

	// If no specific files, snapshot entire workspace
	if files == nil {
		err := filepath.WalkDir(workspacePath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// Skip hidden directories
			if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(workspacePath, path)
			files = append(files, rel)
			return nil
		})
		if err != nil {
			return fmt.Errorf("walk workspace: %w", err)
		}
	}

	maxFileBytes := s.maxFileMB * 1024 * 1024

	for _, relPath := range files {
		srcPath := filepath.Join(workspacePath, relPath)
		info, err := os.Lstat(srcPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Skip missing files
			}
			return fmt.Errorf("stat %s: %w", relPath, err)
		}

		// Skip directories, symlinks, etc.
		if !info.Mode().IsRegular() {
			continue
		}

		// Check file size limit
		if info.Size() > maxFileBytes {
			// Skip oversized files but note in metadata
			continue
		}

		// Check total size limit
		if s.maxSizeMB > 0 {
			maxBytes := int64(s.maxSizeMB) * 1024 * 1024
			if totalSize+info.Size() > maxBytes {
				// Stop snapshotting, we've hit the limit
				break
			}
		}

		// Copy file to checkpoint
		destPath := filepath.Join(filesDir, relPath)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("create parent dir: %w", err)
		}

		hash, err := copyFileWithHash(srcPath, destPath, info.Mode())
		if err != nil {
			return fmt.Errorf("copy %s: %w", relPath, err)
		}

		fileEntries = append(fileEntries, FileEntry{
			Path: relPath,
			Hash: hash,
			Size: info.Size(),
			Mode: info.Mode(),
		})
		totalSize += info.Size()
	}

	// Update metadata with file list
	metaPath := s.metadataPath(sessionID, checkpointID)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return fmt.Errorf("read metadata: %w", err)
	}

	var meta CheckpointMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("unmarshal metadata: %w", err)
	}

	meta.Files = fileEntries
	meta.CanRollback = len(fileEntries) > 0

	data, err = json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	// Clean up checkpoint dir if no files were backed up
	if len(fileEntries) == 0 {
		_ = os.RemoveAll(cpDir)
	}

	return nil
}

// Rollback restores files from checkpoint to workspace.
// Returns list of restored file paths.
func (s *FileCheckpointStorage) Rollback(sessionID, checkpointID string, workspacePath string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, err := s.loadMetadataLocked(sessionID, checkpointID)
	if err != nil {
		return nil, err
	}

	if !meta.CanRollback {
		return nil, ErrRollbackNotSupported
	}

	filesDir := s.filesDir(sessionID, checkpointID)
	var restored []string

	for _, fe := range meta.Files {
		srcPath := filepath.Join(filesDir, fe.Path)
		destPath := filepath.Join(workspacePath, fe.Path)

		// Verify source exists
		if _, err := os.Stat(srcPath); err != nil {
			continue // Skip missing backup files
		}

		// Create parent directory
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return restored, fmt.Errorf("create parent dir for %s: %w", fe.Path, err)
		}

		// Copy file back
		if err := copyFile(srcPath, destPath, fe.Mode); err != nil {
			return restored, fmt.Errorf("restore %s: %w", fe.Path, err)
		}

		// Verify hash
		hash, err := hashFile(destPath)
		if err != nil {
			return restored, fmt.Errorf("hash %s: %w", fe.Path, err)
		}
		if hash != fe.Hash {
			return restored, fmt.Errorf("hash mismatch after restore: %s", fe.Path)
		}

		restored = append(restored, fe.Path)
	}

	return restored, nil
}

// Diff returns files that changed between checkpoint and current workspace.
func (s *FileCheckpointStorage) Diff(sessionID, checkpointID string, workspacePath string) ([]FileDiff, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	meta, err := s.loadMetadataLocked(sessionID, checkpointID)
	if err != nil {
		return nil, err
	}

	var diffs []FileDiff

	// Track files in checkpoint
	checkpointFiles := make(map[string]FileEntry)
	for _, fe := range meta.Files {
		checkpointFiles[fe.Path] = fe
	}

	// Check each checkpoint file against current workspace
	for path, cpFile := range checkpointFiles {
		currentPath := filepath.Join(workspacePath, path)
		info, err := os.Stat(currentPath)
		if err != nil {
			if os.IsNotExist(err) {
				diffs = append(diffs, FileDiff{
					Path:    path,
					Status:  "deleted",
					OldHash: cpFile.Hash,
					OldSize: cpFile.Size,
				})
				continue
			}
			return nil, fmt.Errorf("stat %s: %w", path, err)
		}

		// Check if modified
		currentHash, err := hashFile(currentPath)
		if err != nil {
			return nil, fmt.Errorf("hash %s: %w", path, err)
		}

		if currentHash != cpFile.Hash {
			diffs = append(diffs, FileDiff{
				Path:    path,
				Status:  "modified",
				OldHash: cpFile.Hash,
				NewHash: currentHash,
				OldSize: cpFile.Size,
				NewSize: info.Size(),
			})
		}
	}

	// Check for new files in workspace (files not in checkpoint)
	err = filepath.WalkDir(workspacePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(workspacePath, path)
		if _, exists := checkpointFiles[rel]; !exists {
			info, _ := d.Info()
			hash, _ := hashFile(path)
			diffs = append(diffs, FileDiff{
				Path:    rel,
				Status:  "added",
				NewHash: hash,
				NewSize: info.Size(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk workspace: %w", err)
	}

	// Sort diffs by path
	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].Path < diffs[j].Path
	})

	return diffs, nil
}

// Purge removes checkpoints older than maxAge or exceeding count limit.
func (s *FileCheckpointStorage) Purge(sessionID string, maxAge time.Duration, maxCount int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	checkpoints, err := s.listLocked(sessionID)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	var toDelete []*Checkpoint

	// Mark old checkpoints for deletion
	for _, cp := range checkpoints {
		if maxAge > 0 && now.Sub(cp.CreatedAt) > maxAge {
			toDelete = append(toDelete, cp)
		}
	}

	// Mark excess checkpoints for deletion (keep newest)
	remaining := make([]*Checkpoint, 0)
	for _, cp := range checkpoints {
		found := false
		for _, d := range toDelete {
			if d.ID == cp.ID {
				found = true
				break
			}
		}
		if !found {
			remaining = append(remaining, cp)
		}
	}

	if maxCount > 0 && len(remaining) > maxCount {
		// Sort by creation time (newest first for this operation)
		sort.Slice(remaining, func(i, j int) bool {
			return remaining[i].CreatedAt.After(remaining[j].CreatedAt)
		})
		// Delete oldest excess
		toDelete = append(toDelete, remaining[maxCount:]...)
	}

	// Delete marked checkpoints
	deleted := 0
	for _, cp := range toDelete {
		cpDir := s.checkpointDir(sessionID, cp.ID)
		if err := os.RemoveAll(cpDir); err != nil {
			continue
		}
		deleted++
	}

	// Clean up empty session dir
	sessDir := s.sessionDir(sessionID)
	entries, _ := os.ReadDir(sessDir)
	if len(entries) == 0 {
		_ = os.Remove(sessDir)
	}

	return deleted, nil
}

// listLocked lists checkpoints without locking (caller must hold lock).
func (s *FileCheckpointStorage) listLocked(sessionID string) ([]*Checkpoint, error) {
	sessDir := s.sessionDir(sessionID)
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read session dir: %w", err)
	}

	var checkpoints []*Checkpoint
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := s.metadataPath(sessionID, entry.Name())
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta CheckpointMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		checkpoints = append(checkpoints, &meta.Checkpoint)
	}

	sort.Slice(checkpoints, func(i, j int) bool {
		return checkpoints[i].CreatedAt.Before(checkpoints[j].CreatedAt)
	})

	return checkpoints, nil
}

// loadMetadataLocked loads metadata without locking (caller must hold lock).
func (s *FileCheckpointStorage) loadMetadataLocked(sessionID, checkpointID string) (*CheckpointMetadata, error) {
	metaPath := s.metadataPath(sessionID, checkpointID)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("read metadata: %w", err)
	}

	var meta CheckpointMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return &meta, nil
}

// copyFileWithHash copies a file and returns its SHA-256 hash.
func copyFileWithHash(src, dest string, mode os.FileMode) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return "", err
	}
	defer out.Close()

	h := sha256.New()
	w := io.MultiWriter(out, h)

	if _, err := io.Copy(w, in); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyFile copies a file without computing hash.
func copyFile(src, dest string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return nil
}

// hashFile computes SHA-256 hash of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
