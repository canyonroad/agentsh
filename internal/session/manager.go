package session

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type Session struct {
	mu sync.Mutex

	ID        string
	State     types.SessionState
	CreatedAt time.Time
	Workspace string
	Policy    string

	Cwd     string
	Env     map[string]string
	History []string
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

	id := "session-" + uuid.NewString()
	s := &Session{
		ID:        id,
		State:     types.SessionStateReady,
		CreatedAt: time.Now().UTC(),
		Workspace: abs,
		Policy:    policy,
		Cwd:       "/workspace",
		Env:       map[string]string{},
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

func (s *Session) Builtin(req types.ExecRequest) (handled bool, exitCode int, stdout, stderr []byte) {
	switch req.Command {
	case "cd":
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
		s.mu.Lock()
		out := s.Cwd
		s.History = append(s.History, "pwd")
		s.mu.Unlock()
		b := []byte(out + "\n")
		return true, 0, b, []byte{}
	case "export":
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
		s.mu.Lock()
		out := strings.Join(s.History, "\n") + "\n"
		s.History = append(s.History, "history")
		s.mu.Unlock()
		b := []byte(out)
		return true, 0, b, []byte{}
	default:
		return false, 0, nil, nil
	}
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.History = append(s.History, line)
}
