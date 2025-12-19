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
	"sort"
	"strings"
	"time"
)

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
}

type Config struct {
	TrashDir       string
	Session        string
	Command        string
	HashLimitBytes int64
}

type PurgeOptions struct {
	TTL        time.Duration
	QuotaBytes int64
	Session    string
	Now        time.Time
}

var (
	payloadDirName  = "payload"
	manifestDirName = "manifest"
)

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
			return nil, err
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Created.Before(entries[j].Created)
	})
	return entries, nil
}

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
			return "", fmt.Errorf("destination exists: %s", target)
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

	_ = os.Remove(manPath)
	return target, nil
}

func Purge(trashDir string, opts PurgeOptions) (int, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	entries, err := List(trashDir)
	if err != nil {
		return 0, err
	}
	removed := 0

	if opts.Session != "" && opts.TTL == 0 && opts.QuotaBytes == 0 {
		for _, e := range entries {
			if e.Session == opts.Session {
				if err := removeEntry(trashDir, &e); err != nil {
					return removed, err
				}
				removed++
			}
		}
		return removed, nil
	}

	for _, e := range entries {
		if opts.Session != "" && e.Session != opts.Session {
			continue
		}
		if opts.TTL > 0 && e.Created.Add(opts.TTL).Before(now) {
			if err := removeEntry(trashDir, &e); err != nil {
				return removed, err
			}
			removed++
		}
	}

	if opts.QuotaBytes > 0 {
		entries, err = List(trashDir)
		if err != nil {
			return removed, err
		}
		var total int64
		for _, e := range entries {
			total += e.Size
		}
		for total > opts.QuotaBytes && len(entries) > 0 {
			e := entries[0]
			if err := removeEntry(trashDir, &e); err != nil {
				return removed, err
			}
			total -= e.Size
			entries = entries[1:]
			removed++
		}
	}

	return removed, nil
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
