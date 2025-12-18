package shim

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

type ResolveSessionIDOptions struct {
	Getenv func(string) string

	// WorkDir is used to derive the workspace root when no explicit env var is set.
	// If empty, the resolver falls back to os.Getwd().
	WorkDir string

	// BaseDirs controls where file-backed session ids are stored.
	// If empty, defaults to: /run/agentsh, /tmp/agentsh, <workspaceRoot>/.agentsh
	BaseDirs []string
}

// ResolveSessionID resolves the current agentsh session ID using environment and file-based fallbacks.
//
// Priority:
//  1) AGENTSH_SESSION_ID (return directly; no file path)
//  2) AGENTSH_SESSION_FILE (read/create; returns that file path)
//  3) File-backed fallback (scope controlled by AGENTSH_SESSION_SCOPE=global|workspace)
//
// It returns (sessionID, backingFilePathOrEmpty, error).
func ResolveSessionID(opts ResolveSessionIDOptions) (string, string, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	if v := strings.TrimSpace(getenv("AGENTSH_SESSION_ID")); v != "" {
		return v, "", nil
	}

	if f := strings.TrimSpace(getenv("AGENTSH_SESSION_FILE")); f != "" {
		id, err := readOrCreateSessionIDFile(f)
		if err != nil {
			return "", "", err
		}
		return id, f, nil
	}

	scope := strings.ToLower(strings.TrimSpace(getenv("AGENTSH_SESSION_SCOPE")))
	if scope == "" {
		scope = "workspace"
	}
	if scope != "workspace" && scope != "global" {
		// Be conservative: unknown values behave like workspace.
		scope = "workspace"
	}

	workspaceRoot, err := resolveWorkspaceRoot(getenv, strings.TrimSpace(opts.WorkDir))
	if err != nil {
		return "", "", err
	}

	baseDirs := opts.BaseDirs
	if len(baseDirs) == 0 {
		baseDirs = []string{
			"/run/agentsh",
			"/tmp/agentsh",
			filepath.Join(workspaceRoot, ".agentsh"),
		}
	}

	key := "global"
	if scope == "workspace" {
		key = hashKey(workspaceRoot)
	}

	for _, base := range baseDirs {
		base = strings.TrimSpace(base)
		if base == "" {
			continue
		}
		path, err := ensureSessionFilePath(base, scope, key)
		if err != nil {
			continue
		}
		id, err := readOrCreateSessionIDFile(path)
		if err != nil {
			continue
		}
		return id, path, nil
	}
	// Last-resort behavior: keep the container usable even if all file locations are unwritable.
	// This is intentionally a fixed ID so repeated shim invocations remain consistent.
	return "session-default", "", nil
}

func resolveWorkspaceRoot(getenv func(string) string, workDir string) (string, error) {
	if v := strings.TrimSpace(getenv("AGENTSH_WORKSPACE")); v != "" {
		abs, err := filepath.Abs(v)
		if err == nil {
			return abs, nil
		}
		return filepath.Clean(v), nil
	}

	start := workDir
	if start == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		start = wd
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		abs = filepath.Clean(start)
	}
	if root, ok := findGitRoot(abs); ok {
		return root, nil
	}
	return abs, nil
}

func findGitRoot(start string) (string, bool) {
	dir := filepath.Clean(start)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	// Short but collision-resistant enough for local file names.
	return hex.EncodeToString(h[:])[:16]
}

func ensureSessionFilePath(baseDir, scope, key string) (string, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", err
	}
	switch scope {
	case "global":
		return filepath.Join(baseDir, "session-global.sid"), nil
	case "workspace":
		sdir := filepath.Join(baseDir, "sessions")
		if err := os.MkdirAll(sdir, 0o755); err != nil {
			return "", err
		}
		return filepath.Join(sdir, "workspace-"+key+".sid"), nil
	default:
		return "", fmt.Errorf("unsupported scope %q", scope)
	}
}

func readOrCreateSessionIDFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("session file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return "", err
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()

	b, _ := os.ReadFile(path)
	if id := strings.TrimSpace(string(b)); id != "" {
		return id, nil
	}

	id := "session-" + uuid.NewString()
	if err := f.Truncate(0); err != nil {
		return "", err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return "", err
	}
	if _, err := f.WriteString(id + "\n"); err != nil {
		return "", err
	}
	_ = f.Sync()
	return id, nil
}
