//go:build linux

package ptrace

import (
	"testing"
)

type mockPrometheusCollector struct {
	traceeCount   int
	attachReasons []string
	timeouts      int
}

func (m *mockPrometheusCollector) SetPtraceTraceeCount(n int)      { m.traceeCount = n }
func (m *mockPrometheusCollector) IncPtraceAttachFailure(r string) { m.attachReasons = append(m.attachReasons, r) }
func (m *mockPrometheusCollector) IncPtraceTimeout()               { m.timeouts++ }

func TestPrometheusMetrics(t *testing.T) {
	mock := &mockPrometheusCollector{}
	m := NewPrometheusMetrics(mock)

	m.SetTraceeCount(3)
	if mock.traceeCount != 3 {
		t.Errorf("traceeCount = %d, want 3", mock.traceeCount)
	}

	m.IncAttachFailure("eperm")
	if len(mock.attachReasons) != 1 || mock.attachReasons[0] != "eperm" {
		t.Errorf("attachReasons = %v, want [eperm]", mock.attachReasons)
	}

	m.IncTimeout()
	if mock.timeouts != 1 {
		t.Errorf("timeouts = %d, want 1", mock.timeouts)
	}
}
