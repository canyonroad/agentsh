package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

var (
	ErrSessionExists    = errors.New("session already exists")
	ErrInvalidSessionID = errors.New("invalid session id")
)

var sessionIDRe = regexp.MustCompile(`^session-[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

type Session struct {
	mu sync.Mutex

	ID             string
	State          types.SessionState
	CreatedAt      time.Time
	LastActivity   time.Time
	Workspace      string
	WorkspaceMount string
	Policy         string

	Cwd     string
	Env     map[string]string
	History []string

	currentCommandID string
	currentProcPID   int
	execMu           sync.Mutex

	workspaceUnmount func() error

	proxyURL   string
	proxyClose func() error

	netnsName  string
	netnsClose func() error
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session

	maxSessions int
}

func NewManager(maxSessions int) *Manager {
	if maxSessions <= 0 {
		maxSessions = 100
	}
	return &Manager{
		sessions:    make(map[string]*Session),
		maxSessions: maxSessions,
	}
}

func (m *Manager) Create(workspace, policy string) (*Session, error) {
	return m.CreateWithID("", workspace, policy)
}

func (m *Manager) CreateWithID(id, workspace, policy string) (*Session, error) {
	if workspace == "" {
		return nil, fmt.Errorf("workspace is required")
	}
	abs, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("workspace abs: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace stat: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("workspace must be a directory")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sessions) >= m.maxSessions {
		return nil, fmt.Errorf("max sessions reached")
	}

	if id == "" {
		id = "session-" + uuid.NewString()
	} else if !sessionIDRe.MatchString(id) {
		return nil, ErrInvalidSessionID
	}
	if _, ok := m.sessions[id]; ok {
		return nil, ErrSessionExists
	}
	now := time.Now().UTC()
	s := &Session{
		ID:             id,
		State:          types.SessionStateReady,
		CreatedAt:      now,
		LastActivity:   now,
		Workspace:      abs,
		WorkspaceMount: abs,
		Policy:         policy,
		Cwd:            "/workspace",
		Env:            map[string]string{},
	}
	m.sessions[id] = s
	return s, nil
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *Manager) List() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *Manager) Destroy(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return false
	}
	delete(m.sessions, id)
	return true
}

func (s *Session) Snapshot() types.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return types.Session{
		ID:        s.ID,
		State:     s.State,
		CreatedAt: s.CreatedAt,
		Workspace: s.Workspace,
		Policy:    s.Policy,
		Cwd:       s.Cwd,
	}
}

func (s *Session) LockExec() func() {
	s.execMu.Lock()
	s.mu.Lock()
	s.State = types.SessionStateBusy
	s.LastActivity = time.Now().UTC()
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.State = types.SessionStateReady
		s.currentCommandID = ""
		s.currentProcPID = 0
		s.LastActivity = time.Now().UTC()
		s.mu.Unlock()
		s.execMu.Unlock()
	}
}

func (s *Session) SetCurrentCommandID(commandID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentCommandID = commandID
}

func (s *Session) CurrentCommandID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentCommandID
}

func (s *Session) SetCurrentProcessPID(pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentProcPID = pid
}

func (s *Session) CurrentProcessPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentProcPID
}

func (s *Session) TouchAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.IsZero() {
		t = time.Now().UTC()
	}
	s.LastActivity = t.UTC()
}

func (s *Session) Touch() { s.TouchAt(time.Now().UTC()) }

func (s *Session) Timestamps() (createdAt, lastActivity time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.CreatedAt, s.LastActivity
}

func (s *Session) SetWorkspaceMount(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path != "" {
		s.WorkspaceMount = path
	}
}

func (s *Session) WorkspaceMountPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.WorkspaceMount != "" {
		return s.WorkspaceMount
	}
	return s.Workspace
}

func (s *Session) SetWorkspaceUnmount(fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspaceUnmount = fn
}

func (s *Session) UnmountWorkspace() error {
	s.mu.Lock()
	fn := s.workspaceUnmount
	s.workspaceUnmount = nil
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

func (s *Session) SetProxy(url string, closeFn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxyURL = url
	s.proxyClose = closeFn
}

func (s *Session) ProxyURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proxyURL
}

func (s *Session) CloseProxy() error {
	s.mu.Lock()
	fn := s.proxyClose
	s.proxyClose = nil
	s.proxyURL = ""
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

func (s *Session) SetNetNS(name string, closeFn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.netnsName = name
	s.netnsClose = closeFn
}

func (s *Session) NetNSName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.netnsName
}

func (s *Session) CloseNetNS() error {
	s.mu.Lock()
	fn := s.netnsClose
	s.netnsClose = nil
	s.netnsName = ""
	s.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

func (s *Session) Builtin(req types.ExecRequest) (handled bool, exitCode int, stdout, stderr []byte) {
	switch req.Command {
	case "cd":
		s.Touch()
		target := "/workspace"
		if len(req.Args) > 0 && req.Args[0] != "" {
			target = req.Args[0]
		}
		s.mu.Lock()
		s.Cwd = target
		s.History = append(s.History, "cd "+target)
		s.mu.Unlock()
		return true, 0, []byte{}, []byte{}
	case "pwd":
		s.Touch()
		s.mu.Lock()
		out := s.Cwd
		s.History = append(s.History, "pwd")
		s.mu.Unlock()
		b := []byte(out + "\n")
		return true, 0, b, []byte{}
	case "export":
		s.Touch()
		if len(req.Args) < 1 || !strings.Contains(req.Args[0], "=") {
			msg := []byte("usage: export KEY=value\n")
			return true, 2, []byte{}, msg
		}
		parts := strings.SplitN(req.Args[0], "=", 2)
		s.mu.Lock()
		if s.Env == nil {
			s.Env = map[string]string{}
		}
		s.Env[parts[0]] = parts[1]
		s.History = append(s.History, "export "+req.Args[0])
		s.mu.Unlock()
		return true, 0, []byte{}, []byte{}
	case "unset":
		s.Touch()
		if len(req.Args) < 1 {
			msg := []byte("usage: unset KEY\n")
			return true, 2, []byte{}, msg
		}
		s.mu.Lock()
		delete(s.Env, req.Args[0])
		s.History = append(s.History, "unset "+req.Args[0])
		s.mu.Unlock()
		return true, 0, []byte{}, []byte{}
	case "env":
		s.Touch()
		s.mu.Lock()
		var b strings.Builder
		for k, v := range s.Env {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(v)
			b.WriteString("\n")
		}
		s.History = append(s.History, "env")
		s.mu.Unlock()
		out := []byte(b.String())
		return true, 0, out, []byte{}
	case "history":
		s.Touch()
		s.mu.Lock()
		out := strings.Join(s.History, "\n") + "\n"
		s.History = append(s.History, "history")
		s.mu.Unlock()
		b := []byte(out)
		return true, 0, b, []byte{}
	case "aenv":
		s.Touch()
		_, env, _ := s.GetCwdEnvHistory()
		b, err := json.Marshal(env)
		if err != nil {
			return true, 1, nil, []byte(err.Error() + "\n")
		}
		return true, 0, b, nil
	case "als":
		s.Touch()
		target := ""
		if len(req.Args) > 0 {
			target = req.Args[0]
		}
		virt, real, err := s.resolvePathForBuiltin(target)
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		entries, err := os.ReadDir(real)
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		type item struct {
			Name      string `json:"name"`
			Path      string `json:"path"`
			IsDir     bool   `json:"is_dir"`
			SizeBytes int64  `json:"size_bytes,omitempty"`
			Mode      string `json:"mode,omitempty"`
			MTime     string `json:"mtime,omitempty"`
		}
		out := make([]item, 0, len(entries))
		for _, e := range entries {
			info, _ := e.Info()
			it := item{
				Name:  e.Name(),
				Path:  filepath.ToSlash(filepath.Join(virt, e.Name())),
				IsDir: e.IsDir(),
			}
			if info != nil {
				it.SizeBytes = info.Size()
				it.Mode = info.Mode().String()
				it.MTime = info.ModTime().UTC().Format(time.RFC3339Nano)
			}
			out = append(out, it)
		}
		b, err := json.Marshal(out)
		if err != nil {
			return true, 1, nil, []byte(err.Error() + "\n")
		}
		return true, 0, b, nil
	case "astat":
		s.Touch()
		target := ""
		if len(req.Args) > 0 {
			target = req.Args[0]
		}
		virt, real, err := s.resolvePathForBuiltin(target)
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		info, err := os.Stat(real)
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		out := map[string]any{
			"path":       virt,
			"size_bytes": info.Size(),
			"is_dir":     info.IsDir(),
			"mode":       info.Mode().String(),
			"mtime":      info.ModTime().UTC().Format(time.RFC3339Nano),
		}
		b, err := json.Marshal(out)
		if err != nil {
			return true, 1, nil, []byte(err.Error() + "\n")
		}
		return true, 0, b, nil
	case "acat":
		s.Touch()
		if len(req.Args) < 1 {
			return true, 2, nil, []byte("usage: acat /workspace/path\n")
		}
		virt, real, err := s.resolvePathForBuiltin(req.Args[0])
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		f, err := os.Open(real)
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		defer f.Close()
		const max = 1 * 1024 * 1024
		buf, err := io.ReadAll(io.LimitReader(f, max+1))
		if err != nil {
			return true, 2, nil, []byte(err.Error() + "\n")
		}
		truncated := false
		if len(buf) > max {
			truncated = true
			buf = buf[:max]
		}
		info, _ := f.Stat()
		out := map[string]any{
			"path":      virt,
			"content":   string(buf),
			"truncated": truncated,
		}
		if info != nil {
			out["size_bytes"] = info.Size()
			out["mtime"] = info.ModTime().UTC().Format(time.RFC3339Nano)
		}
		b, err := json.Marshal(out)
		if err != nil {
			return true, 1, nil, []byte(err.Error() + "\n")
		}
		return true, 0, b, nil
	default:
		return false, 0, nil, nil
	}
}

func (s *Session) ApplyPatch(patch types.SessionPatchRequest) error {
	s.Touch()
	s.mu.Lock()
	defer s.mu.Unlock()

	if patch.Cwd != "" {
		cwd := patch.Cwd
		if !strings.HasPrefix(cwd, "/") {
			cwd = filepath.ToSlash(filepath.Join(s.Cwd, cwd))
		}
		cwd = filepath.ToSlash(filepath.Clean(cwd))
		if cwd == "." || cwd == "" {
			cwd = "/workspace"
		}
		if !strings.HasPrefix(cwd, "/workspace") {
			return fmt.Errorf("cwd must be under /workspace")
		}
		s.Cwd = cwd
	}

	if s.Env == nil {
		s.Env = map[string]string{}
	}
	for k, v := range patch.Env {
		if strings.TrimSpace(k) == "" {
			continue
		}
		s.Env[k] = v
	}
	for _, k := range patch.Unset {
		delete(s.Env, k)
	}
	return nil
}

func (s *Session) resolvePathForBuiltin(arg string) (virt string, real string, err error) {
	cwd, _, _ := s.GetCwdEnvHistory()
	virt = cwd
	if strings.TrimSpace(arg) != "" {
		if strings.HasPrefix(arg, "/") {
			virt = arg
		} else {
			virt = filepath.ToSlash(filepath.Join(cwd, arg))
		}
	}
	virt = filepath.ToSlash(filepath.Clean(virt))
	if virt == "." || virt == "" {
		virt = "/workspace"
	}
	if !strings.HasPrefix(virt, "/workspace") {
		return "", "", fmt.Errorf("path must be under /workspace")
	}
	rel := strings.TrimPrefix(virt, "/workspace")
	rel = strings.TrimPrefix(rel, "/")
	root := s.WorkspaceMountPath()
	real = filepath.Clean(filepath.Join(root, filepath.FromSlash(rel)))
	rootClean := filepath.Clean(root)
	if real != rootClean && !strings.HasPrefix(real, rootClean+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("path escapes workspace mount")
	}
	return virt, real, nil
}

func (s *Session) GetCwdEnvHistory() (cwd string, env map[string]string, history []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cwd = s.Cwd
	env = make(map[string]string, len(s.Env))
	for k, v := range s.Env {
		env[k] = v
	}
	history = append([]string(nil), s.History...)
	return
}

func (s *Session) RecordHistory(line string) {
	s.Touch()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.History = append(s.History, line)
}

func (m *Manager) ReapExpired(now time.Time, sessionTimeout, idleTimeout time.Duration) []*Session {
	if sessionTimeout <= 0 && idleTimeout <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var reaped []*Session
	for id, s := range m.sessions {
		s.mu.Lock()
		createdAt := s.CreatedAt
		last := s.LastActivity
		s.mu.Unlock()

		expired := false
		if sessionTimeout > 0 && now.Sub(createdAt) > sessionTimeout {
			expired = true
		}
		if !expired && idleTimeout > 0 && now.Sub(last) > idleTimeout {
			expired = true
		}
		if expired {
			delete(m.sessions, id)
			reaped = append(reaped, s)
		}
	}
	return reaped
}
