package metrics

import (
	"context"
	"github.com/agentsh/agentsh/pkg/types"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestHandlerExportsCountersAndEscapes(t *testing.T) {
	c := New()
	c.IncEvent("foo")
	c.IncEvent("foo")
	c.IncEvent("bar\n\"x\"")
	c.IncEBPFDropped()
	c.IncEBPFAttachFail()
	c.IncEBPFUnavailable()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	c.Handler(HandlerOptions{SessionCount: func() int { return 7 }}).ServeHTTP(rec, req)

	body := rec.Body.String()
	assertContains := func(substr string) {
		t.Helper()
		if !strings.Contains(body, substr) {
			t.Fatalf("metrics output missing %q. Got:\n%s", substr, body)
		}
	}

	assertContains("agentsh_up 1")
	assertContains("agentsh_events_total 3")
	assertContains("agentsh_net_ebpf_dropped_events_total 1")
	assertContains("agentsh_net_ebpf_attach_fail_total 1")
	assertContains("agentsh_net_ebpf_unavailable_total 1")
	assertContains(`agentsh_events_by_type_total{type="bar\\n\\\"x\\\""} 1`)
	assertContains("agentsh_events_by_type_total{type=\"foo\"} 2")
	assertContains("agentsh_sessions_active 7")
}

type fakeEventStore struct {
	mu    sync.Mutex
	count int
}

func (f *fakeEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	return nil
}

func (f *fakeEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}

func (f *fakeEventStore) Close() error { return nil }

func TestWrapEventStoreIncrementsCollector(t *testing.T) {
	c := New()
	inner := &fakeEventStore{}
	store := WrapEventStore(inner, c)

	ev := types.Event{Type: "hello"}
	if err := store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent error: %v", err)
	}

	if got := c.eventsTotal.Load(); got != 1 {
		t.Fatalf("eventsTotal = %d, want 1", got)
	}
	if got := inner.count; got != 1 {
		t.Fatalf("inner count = %d, want 1", got)
	}
}

func TestSnapshotKeysReturnsSorted(t *testing.T) {
	var m sync.Map
	m.Store("b", 1)
	m.Store("a", 1)
	m.Store("c", 1)

	keys := snapshotKeys(&m)
	if strings.Join(keys, ",") != "a,b,c" {
		t.Fatalf("snapshotKeys = %v", keys)
	}
}
