//go:build darwin

package policysock

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testPolicyHandler struct{}

func (m *testPolicyHandler) CheckFile(path, op string) (bool, string) { return true, "" }
func (m *testPolicyHandler) CheckNetwork(ip string, port int, domain string) (bool, string) {
	return true, ""
}
func (m *testPolicyHandler) CheckCommand(cmd string, args []string) (bool, string) {
	return true, ""
}
func (m *testPolicyHandler) ResolveSession(pid int32) string { return "" }

type testStreamEventHandler struct {
	mu     sync.Mutex
	events [][]byte
}

func (m *testStreamEventHandler) HandleESFEvent(_ context.Context, payload []byte) error {
	m.mu.Lock()
	cp := make([]byte, len(payload))
	copy(cp, payload)
	m.events = append(m.events, cp)
	m.mu.Unlock()
	return nil
}

func (m *testStreamEventHandler) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func TestServer_EventStream(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	handler := &testPolicyHandler{}
	srv := NewServer(sockPath, handler)

	mock := &testStreamEventHandler{}
	srv.SetEventHandler(mock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)
	<-srv.Ready()
	if err := srv.StartErr(); err != nil {
		t.Fatalf("server start: %v", err)
	}

	// Connect and send event_stream_init
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send init
	initMsg, _ := json.Marshal(map[string]any{"type": "event_stream_init"})
	initMsg = append(initMsg, '\n')
	conn.Write(initMsg)

	// Read ack
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	var ack map[string]any
	if err := json.Unmarshal(buf[:n], &ack); err != nil {
		t.Fatalf("unmarshal ack: %v (raw: %s)", err, buf[:n])
	}
	if ack["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", ack)
	}

	// Send file events
	for i := 0; i < 3; i++ {
		ev, _ := json.Marshal(map[string]any{
			"type":       "file_event",
			"event_type": "file_open",
			"path":       "/test",
			"pid":        100 + i,
			"session_id": "sess-1",
			"timestamp":  "2026-04-02T00:00:00Z",
		})
		ev = append(ev, '\n')
		conn.Write(ev)
	}

	// Small delay then close connection
	time.Sleep(100 * time.Millisecond)
	conn.Close()

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	if mock.count() != 3 {
		t.Errorf("expected 3 events, got %d", mock.count())
	}
}
