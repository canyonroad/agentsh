package approvals

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type Emitter interface {
	AppendEvent(ctx context.Context, ev types.Event) error
	Publish(ev types.Event)
}

type Request struct {
	ID        string            `json:"id"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	SessionID string            `json:"session_id"`
	CommandID string            `json:"command_id,omitempty"`
	Kind      string            `json:"kind"` // "command" | "file" | "network"
	Target    string            `json:"target,omitempty"`
	Rule      string            `json:"rule,omitempty"`
	Message   string            `json:"message,omitempty"`
	Fields    map[string]any    `json:"fields,omitempty"`
}

type Resolution struct {
	Approved bool      `json:"approved"`
	Reason   string    `json:"reason,omitempty"`
	At       time.Time `json:"at"`
}

type Manager struct {
	mode    string
	timeout time.Duration
	emit    Emitter

	mu      sync.Mutex
	pending map[string]*pending

	promptMu sync.Mutex
}

type pending struct {
	req Request
	ch  chan Resolution
}

func New(mode string, timeout time.Duration, emit Emitter) *Manager {
	if mode == "" {
		mode = "local_tty"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &Manager{
		mode:    mode,
		timeout: timeout,
		emit:    emit,
		pending: make(map[string]*pending),
	}
}

func (m *Manager) ListPending() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Request, 0, len(m.pending))
	now := time.Now().UTC()
	for _, p := range m.pending {
		if p.req.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, p.req)
	}
	return out
}

func (m *Manager) Resolve(id string, approved bool, reason string) bool {
	m.mu.Lock()
	p, ok := m.pending[id]
	if ok {
		delete(m.pending, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	res := Resolution{Approved: approved, Reason: reason, At: time.Now().UTC()}
	select {
	case p.ch <- res:
	default:
	}
	return true
}

func (m *Manager) RequestApproval(ctx context.Context, req Request) (Resolution, error) {
	now := time.Now().UTC()
	if req.ID == "" {
		req.ID = "approval-" + uuid.NewString()
	}
	req.CreatedAt = now
	req.ExpiresAt = now.Add(m.timeout)

	p := &pending{req: req, ch: make(chan Resolution, 1)}

	m.mu.Lock()
	m.pending[req.ID] = p
	m.mu.Unlock()

	m.emitEvent(ctx, "approval_requested", req, nil)

	if m.mode == "local_tty" {
		res, err := m.promptTTY(ctx, req)
		if err != nil {
			_ = m.Resolve(req.ID, false, err.Error())
		} else {
			_ = m.Resolve(req.ID, res.Approved, res.Reason)
		}
	}

	timeout := time.Until(req.ExpiresAt)
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-p.ch:
		m.emitEvent(ctx, "approval_resolved", req, &res)
		return res, nil
	case <-ctx.Done():
		m.Resolve(req.ID, false, "context canceled")
		m.emitEvent(ctx, "approval_resolved", req, &Resolution{Approved: false, Reason: "context canceled", At: time.Now().UTC()})
		return Resolution{Approved: false, Reason: "context canceled", At: time.Now().UTC()}, ctx.Err()
	case <-timer.C:
		m.Resolve(req.ID, false, "approval timeout")
		m.emitEvent(ctx, "approval_resolved", req, &Resolution{Approved: false, Reason: "approval timeout", At: time.Now().UTC()})
		return Resolution{Approved: false, Reason: "approval timeout", At: time.Now().UTC()}, fmt.Errorf("approval timeout")
	}
}

func (m *Manager) emitEvent(ctx context.Context, evType string, req Request, res *Resolution) {
	if m.emit == nil {
		return
	}
	fields := map[string]any{
		"approval_id": req.ID,
		"kind":        req.Kind,
		"target":      req.Target,
		"rule":        req.Rule,
		"message":     req.Message,
	}
	for k, v := range req.Fields {
		fields[k] = v
	}
	if res != nil {
		fields["approved"] = res.Approved
		fields["reason"] = res.Reason
		fields["resolved_at"] = res.At.Format(time.RFC3339Nano)
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      evType,
		SessionID: req.SessionID,
		CommandID: req.CommandID,
		Fields:    fields,
	}
	_ = m.emit.AppendEvent(ctx, ev)
	m.emit.Publish(ev)
}

func (m *Manager) promptTTY(ctx context.Context, req Request) (Resolution, error) {
	m.promptMu.Lock()
	defer m.promptMu.Unlock()

	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return Resolution{}, fmt.Errorf("open /dev/tty: %w", err)
	}
	defer f.Close()

	a, b := challenge()
	fmt.Fprintf(f, "\n=== APPROVAL REQUIRED ===\n")
	fmt.Fprintf(f, "ID: %s\nSession: %s\nCommand: %s\nKind: %s\nTarget: %s\nRule: %s\nMessage: %s\n",
		req.ID, req.SessionID, req.CommandID, req.Kind, req.Target, req.Rule, req.Message)
	fmt.Fprintf(f, "To approve, solve: %d + %d = ?\n> ", a, b)

	reader := bufio.NewReader(f)
	answerLine, _ := reader.ReadString('\n')
	answerLine = strings.TrimSpace(answerLine)
	if answerLine != fmt.Sprintf("%d", a+b) {
		return Resolution{Approved: false, Reason: "challenge failed", At: time.Now().UTC()}, nil
	}

	fmt.Fprintf(f, "Approve? type 'yes' to approve: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))
	if choice == "yes" || choice == "y" {
		return Resolution{Approved: true, Reason: "local tty", At: time.Now().UTC()}, nil
	}
	return Resolution{Approved: false, Reason: "denied", At: time.Now().UTC()}, nil
}

func challenge() (int, int) {
	var b [8]byte
	_, _ = rand.Read(b[:])
	n := binary.LittleEndian.Uint64(b[:])
	a := int(n%50) + 10
	bb := int((n/50)%50) + 10
	return a, bb
}

