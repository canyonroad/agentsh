package composite

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

type fakeEventStore struct {
	appendErr error
	appended  int
	closed    bool
}

func (f *fakeEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	f.appended++
	return f.appendErr
}
func (f *fakeEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return []types.Event{{ID: "x"}}, nil
}
func (f *fakeEventStore) Close() error { f.closed = true; return nil }

type fakeOutputStore struct {
	saveErr error
	readErr error
}

func (f *fakeOutputStore) SaveOutput(ctx context.Context, sessionID, commandID string, stdout, stderr []byte, stdoutTotal, stderrTotal int64, stdoutTrunc, stderrTrunc bool) error {
	return f.saveErr
}
func (f *fakeOutputStore) ReadOutputChunk(ctx context.Context, commandID string, stream string, offset, limit int64) ([]byte, int64, bool, error) {
	if f.readErr != nil {
		return nil, 0, false, f.readErr
	}
	return []byte("ok"), 2, false, nil
}

func TestAppendEventCollectsFirstError(t *testing.T) {
	primary := &fakeEventStore{appendErr: errors.New("primary")}
	secondary := &fakeEventStore{appendErr: errors.New("secondary")}
	s := New(primary, nil, secondary)

	err := s.AppendEvent(context.Background(), types.Event{ID: "1"})
	if err == nil || err.Error() != "primary" {
		t.Fatalf("expected primary error, got %v", err)
	}
	if primary.appended != 1 || secondary.appended != 1 {
		t.Fatalf("expected both stores to receive append, got %d %d", primary.appended, secondary.appended)
	}
}

func TestOutputDelegationAndErrors(t *testing.T) {
	out := &fakeOutputStore{}
	s := New(&fakeEventStore{}, out)
	if err := s.SaveOutput(context.Background(), "s", "c", nil, nil, 0, 0, false, false); err != nil {
		t.Fatalf("SaveOutput unexpected error: %v", err)
	}
	data, total, truncated, err := s.ReadOutputChunk(context.Background(), "c", "stdout", 0, 10)
	if err != nil || string(data) != "ok" || total != 2 || truncated {
		t.Fatalf("ReadOutputChunk unexpected: data=%q total=%d trunc=%v err=%v", data, total, truncated, err)
	}

	sNoOut := New(&fakeEventStore{}, nil)
	if err := sNoOut.SaveOutput(context.Background(), "", "", nil, nil, 0, 0, false, false); err == nil {
		t.Fatal("expected error when output store missing")
	}
	if _, _, _, err := sNoOut.ReadOutputChunk(context.Background(), "", "", 0, 1); err == nil {
		t.Fatal("expected error when output store missing")
	}
}

func TestClosePropagates(t *testing.T) {
	primary := &fakeEventStore{}
	other := &fakeEventStore{}
	s := New(primary, nil, other)
	_ = s.Close()
	if !primary.closed || !other.closed {
		t.Fatalf("expected stores closed")
	}
}

func TestUpsertMCPToolFromEvent_SkipsNonMCPEvents(t *testing.T) {
	primary := &fakeEventStore{}
	s := New(primary, nil)

	// Non-MCP event should be silently skipped
	ev := types.Event{
		Type:   "file_open",
		Fields: map[string]any{"path": "/tmp/test"},
	}
	err := s.UpsertMCPToolFromEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("expected nil error for non-MCP event, got %v", err)
	}
}

func TestUpsertMCPToolFromEvent_SkipsNonSQLiteStore(t *testing.T) {
	primary := &fakeEventStore{}
	s := New(primary, nil)

	// MCP event with fake store should be silently skipped
	ev := types.Event{
		Type: "mcp_tool_seen",
		Fields: map[string]any{
			"server_id": "test-server",
			"tool_name": "test-tool",
			"tool_hash": "abc123",
		},
	}
	err := s.UpsertMCPToolFromEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("expected nil error for non-SQLite store, got %v", err)
	}
}
