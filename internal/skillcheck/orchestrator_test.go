package skillcheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubProvider struct {
	name     string
	findings []Finding
	err      error
	delay    time.Duration
}

func (s stubProvider) Name() string                { return s.name }
func (s stubProvider) Capabilities() []FindingType { return nil }
func (s stubProvider) Scan(ctx context.Context, req ScanRequest) (*ScanResponse, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if s.err != nil {
		return nil, s.err
	}
	return &ScanResponse{Provider: s.name, Findings: s.findings}, nil
}

func TestOrchestrator_MergesFindings(t *testing.T) {
	o := NewOrchestrator(OrchestratorConfig{Providers: map[string]ProviderEntry{
		"a": {Provider: stubProvider{name: "a", findings: []Finding{{Title: "f1"}}}},
		"b": {Provider: stubProvider{name: "b", findings: []Finding{{Title: "f2"}}}},
	}})
	findings, errs := o.ScanAll(context.Background(), ScanRequest{})
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
	if len(errs) != 0 {
		t.Errorf("no errors expected, got %v", errs)
	}
}

func TestOrchestrator_RecordsErrors(t *testing.T) {
	boom := errors.New("boom")
	o := NewOrchestrator(OrchestratorConfig{Providers: map[string]ProviderEntry{
		"a": {Provider: stubProvider{name: "a", err: boom}, OnFailure: "warn"},
		"b": {Provider: stubProvider{name: "b", findings: []Finding{{Title: "f1"}}}},
	}})
	findings, errs := o.ScanAll(context.Background(), ScanRequest{})
	if len(findings) != 1 {
		t.Errorf("expected 1 finding from b, got %d", len(findings))
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Provider != "a" || errs[0].OnFailure != "warn" {
		t.Errorf("error=%+v", errs[0])
	}
}

func TestOrchestrator_PerProviderTimeout(t *testing.T) {
	o := NewOrchestrator(OrchestratorConfig{Providers: map[string]ProviderEntry{
		"slow": {Provider: stubProvider{name: "slow", delay: 200 * time.Millisecond}, Timeout: 10 * time.Millisecond, OnFailure: "warn"},
	}})
	findings, errs := o.ScanAll(context.Background(), ScanRequest{})
	if len(findings) != 0 {
		t.Errorf("expected zero findings on timeout")
	}
	if len(errs) != 1 || !errors.Is(errs[0].Err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %+v", errs)
	}
}

func TestOrchestrator_NilProviderRecordsError(t *testing.T) {
	o := NewOrchestrator(OrchestratorConfig{Providers: map[string]ProviderEntry{
		"nil": {Provider: nil, OnFailure: "deny"},
	}})
	_, errs := o.ScanAll(context.Background(), ScanRequest{})
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
}
