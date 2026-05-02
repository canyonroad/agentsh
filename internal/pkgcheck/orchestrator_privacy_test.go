package pkgcheck

import (
	"context"
	"testing"
	"time"
)

type recordingProvider struct {
	name string
	last []PackageRef
}

func (r *recordingProvider) Name() string                { return r.name }
func (r *recordingProvider) Capabilities() []FindingType  { return nil }
func (r *recordingProvider) CheckBatch(ctx context.Context, req CheckRequest) (*CheckResponse, error) {
	r.last = append([]PackageRef(nil), req.Packages...)
	return &CheckResponse{Provider: r.name}, nil
}

func TestOrchestrator_PrivacyFiltersBeforeProviders(t *testing.T) {
	rp := &recordingProvider{name: "fake"}
	o := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"fake": {Provider: rp, Timeout: time.Second, OnFailure: "warn"},
		},
		PrivacyFilter: NewPrivacyFilter(PrivacyConfig{
			ExternalScanRegistries: []string{"registry.npmjs.org"},
			PrivateScopeDenylist:   []string{"@acme"},
		}),
	})
	req := CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages: []PackageRef{
			{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org"},
			{Name: "@acme/x", Version: "1", Registry: "registry.npmjs.org"},
			{Name: "internal", Version: "0.1", Registry: "artifactory.acme.local"},
		},
	}
	_, _, skipped := o.CheckAllWithPrivacy(context.Background(), req)
	if len(skipped) != 2 {
		t.Fatalf("want 2 skipped, got %d", len(skipped))
	}
	if len(rp.last) != 1 || rp.last[0].Name != "lodash" {
		t.Fatalf("provider should have received lodash only, got %+v", rp.last)
	}
}

func TestOrchestrator_CheckAllStillWorksWithoutPrivacyFilter(t *testing.T) {
	rp := &recordingProvider{name: "fake"}
	o := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"fake": {Provider: rp, Timeout: time.Second, OnFailure: "warn"},
		},
	})
	req := CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages:  []PackageRef{{Name: "lodash", Version: "4.17.21"}},
	}
	_, _ = o.CheckAll(context.Background(), req)
	if len(rp.last) != 1 {
		t.Fatalf("backward-compat CheckAll should pass packages through unchanged")
	}
}

func TestOrchestrator_AllSkippedDoesNotInvokeProviders(t *testing.T) {
	rp := &recordingProvider{name: "fake"}
	calls := 0
	rp2 := &recordingProvider{name: "fake-with-counter"}
	_ = rp2 // unused but kept for symmetry; recordingProvider records calls already
	o := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"fake": {Provider: rp, Timeout: time.Second, OnFailure: "warn"},
		},
		PrivacyFilter: NewPrivacyFilter(PrivacyConfig{
			ExternalScanRegistries: []string{"registry.npmjs.org"},
			PrivateScopeDenylist:   []string{"@acme"},
		}),
	})
	req := CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages: []PackageRef{
			{Name: "@acme/x", Version: "1", Registry: "registry.npmjs.org"},
			{Name: "internal", Version: "0.1", Registry: "artifactory.acme.local"},
		},
	}
	findings, errs, skipped := o.CheckAllWithPrivacy(context.Background(), req)
	if findings != nil {
		t.Errorf("findings should be nil when all packages skipped, got %+v", findings)
	}
	if errs != nil {
		t.Errorf("errs should be nil when no provider was invoked, got %+v", errs)
	}
	if len(skipped) != 2 {
		t.Errorf("want 2 skipped, got %d", len(skipped))
	}
	if rp.last != nil {
		t.Errorf("provider must not be invoked when all packages skipped; got last=%+v", rp.last)
	}
	_ = calls
}
