package skillcheck

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoaderLimits caps the size of skills the loader will accept.
type LoaderLimits struct {
	PerFileBytes int64
	TotalBytes   int64
}

// DefaultLoaderLimits returns the spec defaults: 256 KiB per file, 4 MiB total.
func DefaultLoaderLimits() LoaderLimits {
	return LoaderLimits{
		PerFileBytes: 256 * 1024,
		TotalBytes:   4 * 1024 * 1024,
	}
}

// LoadSkill walks a skill directory, parses SKILL.md frontmatter, hashes
// the file tree, and returns a populated SkillRef plus the file contents
// keyed by relative slash-separated path.
func LoadSkill(path string, limits LoaderLimits) (*SkillRef, map[string][]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("loader: abs(%s): %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("loader: stat: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("loader: %s is not a directory", abs)
	}

	files := map[string][]byte{}
	var totalSize int64

	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip .git internals from the file map; we read .git/config separately.
			if filepath.Base(p) == ".git" && p != abs {
				return filepath.SkipDir
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		size := fi.Size()
		if size > limits.PerFileBytes {
			return fmt.Errorf("loader: per-file size limit exceeded for %s (%d > %d)", p, size, limits.PerFileBytes)
		}
		totalSize += size
		if totalSize > limits.TotalBytes {
			return fmt.Errorf("loader: total size limit exceeded (%d > %d)", totalSize, limits.TotalBytes)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = data
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}

	skillMD, ok := files["SKILL.md"]
	if !ok {
		return nil, nil, fmt.Errorf("loader: no SKILL.md found in %s", abs)
	}
	manifest, err := parseFrontmatter(skillMD)
	if err != nil {
		return nil, nil, fmt.Errorf("loader: parse SKILL.md frontmatter: %w", err)
	}

	ref := &SkillRef{
		Name:     filepath.Base(abs),
		Path:     abs,
		SHA256:   hashFiles(files),
		Manifest: manifest,
	}
	if manifest.Name != "" {
		ref.Name = manifest.Name
	}
	ref.Origin = detectOrigin(abs, manifest)
	return ref, files, nil
}

func parseFrontmatter(src []byte) (SkillManifest, error) {
	const fence = "---"
	if !bytes.HasPrefix(src, []byte(fence)) {
		return SkillManifest{}, nil // no frontmatter; return empty
	}
	rest := src[len(fence):]
	end := bytes.Index(rest, []byte("\n"+fence))
	if end < 0 {
		return SkillManifest{}, fmt.Errorf("unterminated frontmatter")
	}
	body := rest[:end]
	var m SkillManifest
	if err := yaml.Unmarshal(body, &m); err != nil {
		return SkillManifest{}, err
	}
	return m, nil
}

func hashFiles(files map[string][]byte) string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	var lenBuf [8]byte
	for _, k := range keys {
		data := files[k]
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(k)))
		h.Write(lenBuf[:])
		h.Write([]byte(k))
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(data)))
		h.Write(lenBuf[:])
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func detectOrigin(skillDir string, manifest SkillManifest) *GitOrigin {
	gitConfigPath := filepath.Join(skillDir, ".git", "config")
	if data, err := os.ReadFile(gitConfigPath); err == nil {
		if url := parseGitOriginURL(data); url != "" {
			return &GitOrigin{URL: canonicalizeGitURL(url)}
		}
	}
	if manifest.Source != "" {
		return &GitOrigin{URL: canonicalizeGitURL(manifest.Source)}
	}
	return nil
}

// parseGitOriginURL extracts the [remote "origin"] url= line from a .git/config.
func parseGitOriginURL(data []byte) string {
	lines := strings.Split(string(data), "\n")
	inOrigin := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[remote") {
			inOrigin = strings.Contains(trimmed, `"origin"`)
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inOrigin = false
			continue
		}
		if inOrigin && strings.HasPrefix(trimmed, "url") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// canonicalizeGitURL converts SSH-style git URLs to https form so skills.sh
// lookups work uniformly.
func canonicalizeGitURL(u string) string {
	if strings.HasPrefix(u, "git@github.com:") {
		rest := strings.TrimPrefix(u, "git@github.com:")
		rest = strings.TrimSuffix(rest, ".git")
		return "https://github.com/" + rest
	}
	return strings.TrimSuffix(u, ".git")
}
