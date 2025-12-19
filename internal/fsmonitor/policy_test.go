package fsmonitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/fsmonitor/audit"
	"github.com/agentsh/agentsh/internal/trash"
)

type stubSink struct {
	events []audit.Event
	err    error
}

func (s *stubSink) Log(ev audit.Event) error {
	s.events = append(s.events, ev)
	return s.err
}

func TestApplyAuditPolicy_Monitor(t *testing.T) {
	sink := &stubSink{}
	cfg := config.FUSEAuditConfig{Mode: "monitor"}
	called := false
	errno := applyAuditPolicy(context.Background(), &FUSEAuditHooks{Sink: sink, Config: cfg}, "sess", "unlink", "/workspace/a", "", "", nil, func() syscall.Errno {
		called = true
		return 0
	})
	if errno != 0 {
		t.Fatalf("expected success errno 0, got %d", errno)
	}
	if !called {
		t.Fatalf("expected action to run")
	}
	if len(sink.events) != 1 || sink.events[0].Result != "allowed" {
		t.Fatalf("expected allowed event, got %+v", sink.events)
	}
}

func TestApplyAuditPolicy_SoftBlock(t *testing.T) {
	sink := &stubSink{}
	cfg := config.FUSEAuditConfig{Mode: "soft_block"}
	called := false
	errno := applyAuditPolicy(context.Background(), &FUSEAuditHooks{Sink: sink, Config: cfg}, "sess", "unlink", "/workspace/a", "", "", nil, func() syscall.Errno {
		called = true
		return 0
	})
	if errno != syscall.EACCES {
		t.Fatalf("expected EACCES, got %d", errno)
	}
	if called {
		t.Fatalf("action should not run in soft_block")
	}
	if len(sink.events) != 1 || sink.events[0].Result != "blocked" {
		t.Fatalf("expected blocked event, got %+v", sink.events)
	}
}

func TestApplyAuditPolicy_StrictLoggingFailure(t *testing.T) {
	sink := &stubSink{err: errors.New("queue full")}
	cfg := config.FUSEAuditConfig{Mode: "strict"}
	errno := applyAuditPolicy(context.Background(), &FUSEAuditHooks{Sink: sink, Config: cfg}, "sess", "unlink", "/workspace/a", "", "", nil, func() syscall.Errno {
		return 0
	})
	if errno != syscall.EIO {
		t.Fatalf("expected EIO when logging fails in strict mode, got %d", errno)
	}
}

func TestApplyAuditPolicy_Disabled(t *testing.T) {
	enabled := false
	cfg := config.FUSEAuditConfig{Enabled: &enabled, Mode: "soft_block"}
	called := false
	errno := applyAuditPolicy(context.Background(), &FUSEAuditHooks{Sink: &stubSink{}, Config: cfg}, "sess", "unlink", "/workspace/a", "", "", nil, func() syscall.Errno {
		called = true
		return 0
	})
	if errno != 0 {
		t.Fatalf("expected success, got %d", errno)
	}
	if !called {
		t.Fatalf("expected action to run when audit disabled")
	}
}

func TestApplyAuditPolicy_SoftDeleteUsesDivert(t *testing.T) {
	sink := &stubSink{}
	cfg := config.FUSEAuditConfig{Mode: "soft_delete"}
	divertCalled := false
	errno := applyAuditPolicy(context.Background(), &FUSEAuditHooks{Sink: sink, Config: cfg}, "sess", "unlink", "/workspace/a", "", "/real/a", func() (*trash.Entry, error) {
		divertCalled = true
		return &trash.Entry{Token: "tok1"}, nil
	}, func() syscall.Errno {
		t.Fatalf("run should not be called in soft_delete")
		return 0
	})
	if errno != 0 {
		t.Fatalf("expected success, got %d", errno)
	}
	if !divertCalled {
		t.Fatalf("expected divert to be called")
	}
	if len(sink.events) != 1 || sink.events[0].TrashToken != "tok1" || sink.events[0].Result != "diverted" {
		t.Fatalf("expected diverted event with token, got %+v", sink.events)
	}
}

func TestApplyAuditPolicy_RecordsSizeAndNlink(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(fp, []byte("abcd"), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &stubSink{}
	cfg := config.FUSEAuditConfig{Mode: "monitor"}
	errno := applyAuditPolicy(context.Background(), &FUSEAuditHooks{Sink: sink, Config: cfg}, "sess", "unlink", "/workspace/f.txt", "", fp, nil, func() syscall.Errno {
		return 0
	})
	if errno != 0 {
		t.Fatalf("expected success, got %d", errno)
	}
	if len(sink.events) != 1 {
		t.Fatalf("expected one event, got %d", len(sink.events))
	}
	ev := sink.events[0]
	if ev.Size == 0 {
		t.Fatalf("expected size recorded, got 0")
	}
	if ev.LinkCount == 0 {
		t.Fatalf("expected nlink recorded, got 0")
	}
}
