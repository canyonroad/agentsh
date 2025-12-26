package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewPrometheusCollector(t *testing.T) {
	c := NewPrometheusCollector()
	if c == nil {
		t.Fatal("NewPrometheusCollector() returned nil")
	}
}

func TestPrometheusCollector_SessionMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	// Test active sessions
	c.IncSessionActive()
	c.IncSessionActive()
	if c.sessionsActive.Load() != 2 {
		t.Errorf("sessionsActive = %d, want 2", c.sessionsActive.Load())
	}

	c.DecSessionActive()
	if c.sessionsActive.Load() != 1 {
		t.Errorf("sessionsActive = %d, want 1", c.sessionsActive.Load())
	}

	// Test session created counter
	c.IncSessionCreated("created", "tenant-1")
	c.IncSessionCreated("created", "tenant-1")
	c.IncSessionCreated("created", "tenant-2")

	// Test session duration recording
	c.RecordSessionDuration("tenant-1", "completed", 30*time.Second)
	c.RecordSessionDuration("tenant-1", "completed", 60*time.Second)
}

func TestPrometheusCollector_OperationMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	// Test operation counter
	c.IncOperation("file_read", "allow")
	c.IncOperation("file_read", "allow")
	c.IncOperation("file_read", "deny")
	c.IncOperation("net_connect", "allow")

	// Test operation latency
	c.RecordOperationLatency("file_read", 100*time.Microsecond)
	c.RecordOperationLatency("file_read", 200*time.Microsecond)
	c.RecordOperationLatency("net_connect", 500*time.Microsecond)
}

func TestPrometheusCollector_ApprovalMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	// Test pending approvals
	c.IncApprovalPending()
	c.IncApprovalPending()
	if c.approvalsPending.Load() != 2 {
		t.Errorf("approvalsPending = %d, want 2", c.approvalsPending.Load())
	}

	c.DecApprovalPending()
	if c.approvalsPending.Load() != 1 {
		t.Errorf("approvalsPending = %d, want 1", c.approvalsPending.Load())
	}

	// Test approval latency
	c.RecordApprovalLatency(5 * time.Second)
	c.RecordApprovalLatency(30 * time.Second)
}

func TestPrometheusCollector_PolicyMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	c.RecordPolicyEvalLatency(10 * time.Microsecond)
	c.RecordPolicyEvalLatency(50 * time.Microsecond)
	c.RecordPolicyEvalLatency(100 * time.Microsecond)
}

func TestPrometheusCollector_LegacyEventMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	c.IncEvent("file_read")
	c.IncEvent("file_read")
	c.IncEvent("net_connect")
	c.IncEvent("") // Should become "unknown"

	if c.eventsTotal.Load() != 4 {
		t.Errorf("eventsTotal = %d, want 4", c.eventsTotal.Load())
	}
}

func TestPrometheusCollector_EBPFMetrics(t *testing.T) {
	c := NewPrometheusCollector()

	c.IncEBPFDropped()
	c.IncEBPFDropped()
	if c.ebpfDropped.Load() != 2 {
		t.Errorf("ebpfDropped = %d, want 2", c.ebpfDropped.Load())
	}

	c.IncEBPFAttachFail()
	if c.ebpfAttachFail.Load() != 1 {
		t.Errorf("ebpfAttachFail = %d, want 1", c.ebpfAttachFail.Load())
	}

	c.IncEBPFUnavailable()
	if c.ebpfUnavailable.Load() != 1 {
		t.Errorf("ebpfUnavailable = %d, want 1", c.ebpfUnavailable.Load())
	}
}

func TestPrometheusCollector_NilSafety(t *testing.T) {
	var c *PrometheusCollector

	// None of these should panic
	c.IncSessionActive()
	c.DecSessionActive()
	c.IncSessionCreated("created", "tenant")
	c.RecordSessionDuration("tenant", "completed", time.Second)
	c.IncOperation("file_read", "allow")
	c.RecordOperationLatency("file_read", time.Microsecond)
	c.IncApprovalPending()
	c.DecApprovalPending()
	c.RecordApprovalLatency(time.Second)
	c.RecordPolicyEvalLatency(time.Microsecond)
	c.IncEvent("test")
	c.IncEBPFDropped()
	c.IncEBPFAttachFail()
	c.IncEBPFUnavailable()
}

func TestPrometheusCollector_Handler(t *testing.T) {
	c := NewPrometheusCollector()

	// Add some metrics
	c.IncSessionActive()
	c.IncSessionCreated("created", "tenant-1")
	c.IncOperation("file_read", "allow")
	c.RecordOperationLatency("file_read", 100*time.Microsecond)
	c.RecordSessionDuration("tenant-1", "completed", 30*time.Second)
	c.RecordApprovalLatency(5 * time.Second)
	c.RecordPolicyEvalLatency(10 * time.Microsecond)
	c.IncEvent("file_read")
	c.IncEBPFDropped()

	// Create handler and request
	handler := c.Handler(HandlerOptions{})
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body := w.Body.String()

	// Check for expected metrics
	expectedMetrics := []string{
		"agentsh_up 1",
		"agentsh_sessions_active",
		"agentsh_sessions_total",
		"agentsh_operations_total",
		"agentsh_operation_latency_seconds",
		"agentsh_approvals_pending",
		"agentsh_approval_latency_seconds",
		"agentsh_policy_eval_latency_seconds",
		"agentsh_events_total",
		"agentsh_events_by_type_total",
		"agentsh_net_ebpf_dropped_events_total",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("response missing metric: %s", metric)
		}
	}
}

func TestEscapeLabelValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with\\backslash", "with\\\\backslash"},
		{"with\"quote", "with\\\"quote"},
		{"with\nnewline", "with\\nnewline"},
		{"all\\of\"these\n", "all\\\\of\\\"these\\n"},
	}

	for _, tt := range tests {
		got := escapeLabelValue(tt.input)
		if got != tt.want {
			t.Errorf("escapeLabelValue(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
