package trash

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Xattr represents an extended attribute (Linux/macOS).
type Xattr struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// Entry describes one diverted item.
type Entry struct {
	Token        string      `json:"token"`
	OriginalPath string      `json:"original_path"`
	TrashPath    string      `json:"trash_path"`
	Size         int64       `json:"size"`
	Hash         string      `json:"hash,omitempty"`
	HashAlgo     string      `json:"hash_algo,omitempty"`
	Mode         os.FileMode `json:"mode"`
	UID          int         `json:"uid"`
	GID          int         `json:"gid"`
	Mtime        time.Time   `json:"mtime"`
	Session      string      `json:"session"`
	Command      string      `json:"command"`
	Created      time.Time   `json:"created"`

	// Platform identifies which OS created this entry
	Platform string `json:"platform,omitempty"`

	// Windows-specific metadata
	WinAttrs    uint32 `json:"win_attrs,omitempty"`    // FILE_ATTRIBUTE_*
	WinSecurity []byte `json:"win_security,omitempty"` // Security descriptor

	// macOS-specific metadata
	MacFlags uint32 `json:"mac_flags,omitempty"` // chflags

	// Extended attributes (Linux/macOS)
	Xattrs []Xattr `json:"xattrs,omitempty"`
}

// Config configures trash operations.
type Config struct {
	TrashDir         string
	Session          string
	Command          string
	HashLimitBytes   int64
	PreserveXattrs   bool // Preserve extended attributes (macOS/Linux)
	PreserveSecurity bool // Preserve security descriptors (Windows)
}

// PurgeOptions controls trash cleanup.
type PurgeOptions struct {
	TTL        time.Duration // Remove entries older than this
	QuotaBytes int64         // Max total trash size
	QuotaCount int           // Max number of entries
	Session    string        // Only purge entries from this session (empty = all)
	DryRun     bool          // Don't actually delete, just report
	Now        time.Time     // Current time (for testing)
}

// PurgeResult reports what was cleaned up.
type PurgeResult struct {
	EntriesRemoved int
	BytesReclaimed int64
	Entries        []Entry // If DryRun, what would be removed
}

var (
	payloadDirName  = "payload"
	manifestDirName = "manifest"
)

// Divert moves a file/directory to trash instead of deleting it.
func Divert(path string, cfg Config) (*Entry, error) {
	if cfg.TrashDir == "" {
		return nil, errors.New("trash dir required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	size, err := sizeOf(path, info)
	if err != nil {
		return nil, err
	}
	var hashVal, hashAlgo string
	if cfg.HashLimitBytes > 0 && !info.IsDir() && size <= cfg.HashLimitBytes {
		if h, err := hashFile(path, sha256.New(), "sha256"); err == nil {
			hashVal, hashAlgo = h.Value, h.Algo
		}
	}
	token := fmt.Sprintf("%d", time.Now().UnixNano())
	entry := &Entry{
		Token:        token,
		OriginalPath: path,
		TrashPath:    filepath.Join(cfg.TrashDir, payloadDirName, token),
		Size:         size,
		Hash:         hashVal,
		HashAlgo:     hashAlgo,
		Mode:         info.Mode(),
		Mtime:        info.ModTime(),
		Session:      cfg.Session,
		Command:      cfg.Command,
		Created:      time.Now().UTC(),
		Platform:     runtime.GOOS,
	}

	// Capture platform-specific metadata
	if err := capturePlatformMetadata(path, info, entry, cfg); err != nil {
		// Log but don't fail - metadata is nice-to-have
		// In production, you'd use a logger here
	}

	if err := os.MkdirAll(filepath.Dir(entry.TrashPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.Rename(path, entry.TrashPath); err != nil {
		// Fallback to copy then remove.
		if err := copyPath(path, entry.TrashPath, info); err != nil {
			return nil, fmt.Errorf("divert (copy fallback): %w", err)
		}
		if err := os.RemoveAll(path); err != nil {
			return nil, fmt.Errorf("cleanup source: %w", err)
		}
	}

	if err := writeManifest(cfg.TrashDir, entry); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	return entry, nil
}

// List returns all entries in the trash, sorted by creation time (oldest first).
func List(trashDir string) ([]Entry, error) {
	manDir := filepath.Join(trashDir, manifestDirName)
	files, err := os.ReadDir(manDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []Entry
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		var e Entry
		b, err := os.ReadFile(filepath.Join(manDir, f.Name()))
		if err != nil {
			continue // Skip unreadable manifests
		}
		if err := json.Unmarshal(b, &e); err != nil {
			continue // Skip corrupt manifests
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Created.Before(entries[j].Created)
	})
	return entries, nil
}

// Restore recovers a file from trash.
func Restore(trashDir, token, dest string, force bool) (string, error) {
	entry, manPath, err := readManifest(trashDir, token)
	if err != nil {
		return "", err
	}
	payload := entry.TrashPath
	target := dest
	if target == "" {
		target = entry.OriginalPath
	}

	if !force {
		if _, err := os.Lstat(target); err == nil {
			return "", fmt.Errorf("destination exists: %s (use force=true to overwrite)", target)
		}
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(payload, target); err != nil {
		// Fallback copy.
		info, err2 := os.Lstat(payload)
		if err2 != nil {
			return "", err2
		}
		if err := copyPath(payload, target, info); err != nil {
			return "", err
		}
		if err := os.RemoveAll(payload); err != nil {
			return "", err
		}
	}

	// Integrity check if hash present.
	if entry.Hash != "" {
		algo := entry.HashAlgo
		if algo == "" {
			algo = "sha256"
		}
		var h hash.Hash
		switch strings.ToLower(algo) {
		case "sha256":
			h = sha256.New()
		default:
			return "", fmt.Errorf("unsupported hash algo %q", algo)
		}
		actual, err := hashFile(target, h, algo)
		if err != nil {
			return "", fmt.Errorf("hash target: %w", err)
		}
		if actual.Value != entry.Hash {
			return "", fmt.Errorf("hash mismatch on restore: expected %s got %s", entry.Hash, actual.Value)
		}
	}

	// Restore platform-specific metadata
	if err := restorePlatformMetadata(target, entry); err != nil {
		// Log but don't fail
	}

	_ = os.Remove(manPath)
	return target, nil
}

// Purge removes old entries from trash based on options.
// Deprecated: Use PurgeWithResult for more detailed results.
func Purge(trashDir string, opts PurgeOptions) (int, error) {
	result, err := PurgeWithResult(trashDir, opts)
	if err != nil {
		return 0, err
	}
	return result.EntriesRemoved, nil
}

// PurgeWithResult removes old entries from trash and returns detailed results.
func PurgeWithResult(trashDir string, opts PurgeOptions) (*PurgeResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	entries, err := List(trashDir)
	if err != nil {
		return nil, err
	}

	result := &PurgeResult{}
	var toRemove []Entry

	// Filter by session if specified
	if opts.Session != "" {
		filtered := make([]Entry, 0, len(entries))
		for _, e := range entries {
			if e.Session == opts.Session {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	// Special case: if Session is set but no TTL or quota constraints,
	// purge all entries for that session
	if opts.Session != "" && opts.TTL == 0 && opts.QuotaBytes == 0 && opts.QuotaCount == 0 {
		toRemove = entries
	} else {
		// Apply TTL filter
		if opts.TTL > 0 {
			for _, e := range entries {
				if e.Created.Add(opts.TTL).Before(now) {
					toRemove = append(toRemove, e)
				}
			}
		}
	}

	// Build remaining list (entries not in toRemove)
	remaining := make([]Entry, 0)
	for _, e := range entries {
		found := false
		for _, r := range toRemove {
			if r.Token == e.Token {
				found = true
				break
			}
		}
		if !found {
			remaining = append(remaining, e)
		}
	}

	// Apply count quota (remove oldest first)
	if opts.QuotaCount > 0 && len(remaining) > opts.QuotaCount {
		excess := remaining[:len(remaining)-opts.QuotaCount]
		toRemove = append(toRemove, excess...)
		remaining = remaining[len(remaining)-opts.QuotaCount:]
	}

	// Apply bytes quota
	if opts.QuotaBytes > 0 {
		var total int64
		for _, e := range remaining {
			total += e.Size
		}
		for total > opts.QuotaBytes && len(remaining) > 0 {
			oldest := remaining[0]
			toRemove = append(toRemove, oldest)
			total -= oldest.Size
			remaining = remaining[1:]
		}
	}

	// Perform removal (or just report if DryRun)
	if opts.DryRun {
		result.Entries = toRemove
		for _, e := range toRemove {
			result.EntriesRemoved++
			result.BytesReclaimed += e.Size
		}
	} else {
		for _, e := range toRemove {
			if err := removeEntry(trashDir, &e); err != nil {
				return result, fmt.Errorf("remove entry %s: %w", e.Token, err)
			}
			result.EntriesRemoved++
			result.BytesReclaimed += e.Size
		}
	}

	return result, nil
}

func writeManifest(trashDir string, e *Entry) error {
	manDir := filepath.Join(trashDir, manifestDirName)
	if err := os.MkdirAll(manDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(manDir, e.Token+".json")
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o640)
}

func readManifest(trashDir, token string) (*Entry, string, error) {
	manPath := filepath.Join(trashDir, manifestDirName, token+".json")
	b, err := os.ReadFile(manPath)
	if err != nil {
		return nil, "", err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, "", err
	}
	return &e, manPath, nil
}

func removeEntry(trashDir string, e *Entry) error {
	manPath := filepath.Join(trashDir, manifestDirName, e.Token+".json")
	payload := e.TrashPath
	_ = os.Remove(manPath)
	return os.RemoveAll(payload)
}

func sizeOf(path string, info os.FileInfo) (int64, error) {
	if !info.IsDir() {
		return info.Size(), nil
	}
	var total int64
	err := filepath.Walk(path, func(_ string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total, err
}

func copyPath(src, dest string, info os.FileInfo) error {
	if info.IsDir() {
		if err := os.MkdirAll(dest, info.Mode()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			childSrc := filepath.Join(src, ent.Name())
			childDest := filepath.Join(dest, ent.Name())
			childInfo, err := os.Lstat(childSrc)
			if err != nil {
				return err
			}
			if err := copyPath(childSrc, childDest, childInfo); err != nil {
				return err
			}
		}
		return nil
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

type fileHash struct {
	Value string
	Algo  string
}

func hashFile(path string, h hash.Hash, algo string) (*fileHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return &fileHash{Value: fmt.Sprintf("%x", h.Sum(nil)), Algo: algo}, nil
}
