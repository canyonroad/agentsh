package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewDebugger(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("quit\n"),
	})

	if dbg == nil {
		t.Fatal("expected non-nil debugger")
	}
}

func TestDebugger_Run_Quit(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("quit\n"),
	})

	ctx := context.Background()
	if err := dbg.Run(ctx); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "debugger") {
		t.Error("should show debugger header")
	}
	if !strings.Contains(output, "Detaching") {
		t.Error("should show detaching message")
	}
}

func TestDebugger_Run_Help(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("help\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "Commands:") {
		t.Error("should show commands")
	}
	if !strings.Contains(output, "events") {
		t.Error("should show events command")
	}
}

func TestDebugger_Run_Events(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
		events: []Event{
			{Type: "file_read", Path: "/test.txt", Decision: "allow", Latency: "1ms"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("events\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "file_read") {
		t.Error("should show events")
	}
}

func TestDebugger_Run_Stats(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running", StartTime: time.Now()},
			EventCount:  100,
			ResourceUsage: &ResourceUsage{
				CPUPercent: 50,
				MemoryMB:   256,
			},
		},
		events: []Event{
			{Type: "file_read", Decision: "allow"},
			{Type: "file_read", Decision: "deny"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("stats\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "Events: 100") {
		t.Error("should show event count")
	}
	if !strings.Contains(output, "CPU") {
		t.Error("should show CPU usage")
	}
}

func TestDebugger_Run_Trace(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("trace on\ntrace\ntrace off\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "Tracing enabled") {
		t.Error("should enable tracing")
	}
	if !strings.Contains(output, "Tracing disabled") {
		t.Error("should disable tracing")
	}
}

func TestDebugger_Run_Info(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{
				ID:      "sess-1",
				State:   "running",
				AgentID: "agent-1",
			},
			Workspace: "/workspace",
			Metadata:  map[string]string{"env": "prod"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("info\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "sess-1") {
		t.Error("should show session ID")
	}
	if !strings.Contains(output, "agent-1") {
		t.Error("should show agent ID")
	}
	if !strings.Contains(output, "/workspace") {
		t.Error("should show workspace")
	}
}

func TestDebugger_Run_Pending(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
		events: []Event{
			{Type: "file_read", Path: "/sensitive", Decision: "pending"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("pending\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "Pending approvals: 1") {
		t.Error("should show pending count")
	}
}

func TestDebugger_Run_UnknownCommand(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    buf,
		Input:     strings.NewReader("unknowncmd\nquit\n"),
	})

	ctx := context.Background()
	dbg.Run(ctx)

	output := buf.String()
	if !strings.Contains(output, "Unknown command") {
		t.Error("should show unknown command message")
	}
}

func TestDebugger_IsRunning(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    &bytes.Buffer{},
		Input:     strings.NewReader("quit\n"),
	})

	if dbg.IsRunning() {
		t.Error("should not be running before Run()")
	}
}

func TestDebugger_Run_DoubleRun(t *testing.T) {
	client := &mockClient{
		sessionDetail: &SessionDetail{
			SessionInfo: SessionInfo{ID: "sess-1", State: "running"},
		},
	}

	// Use a channel to coordinate the test
	started := make(chan struct{})
	done := make(chan struct{})

	dbg := NewDebugger(DebuggerConfig{
		Client:    client,
		SessionID: "sess-1",
		Output:    &bytes.Buffer{},
		Input:     &blockingReader{started: started, done: done},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		dbg.Run(ctx)
	}()

	// Wait for first Run to start
	<-started

	// Try to run again - should error
	err := dbg.Run(ctx)
	if err == nil {
		t.Error("should error when running twice")
	}

	// Clean up
	close(done)
}

// blockingReader blocks until done is closed
type blockingReader struct {
	started chan struct{}
	done    chan struct{}
	once    bool
}

func (r *blockingReader) Read(p []byte) (n int, err error) {
	if !r.once {
		r.once = true
		close(r.started)
	}
	<-r.done
	copy(p, "quit\n")
	return 5, nil
}
