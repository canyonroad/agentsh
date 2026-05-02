package pkgcheck_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/agentsh/agentsh/internal/pkgcheck/provider"
	"github.com/agentsh/agentsh/internal/policy"
)

func TestIntegration_SocketDownDegradesToOSV(t *testing.T) {
	// Socket: returns 500 every call.
	socketSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer socketSrv.Close()

	// OSV: returns one critical vuln for lodash.
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-xxxx","summary":"sample","severity":[{"type":"CVSS_V3","score":"9.8"}]}]}]}`))
	}))
	defer osvSrv.Close()

	pf := pkgcheck.NewPrivacyFilter(pkgcheck.PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
		PrivateScopeDenylist:   []string{"@acme"},
	})

	o := pkgcheck.NewOrchestrator(pkgcheck.OrchestratorConfig{
		PrivacyFilter: pf,
		Providers: map[string]pkgcheck.ProviderEntry{
			"socket": {
				Provider:  provider.NewSocketProvider(provider.SocketConfig{BaseURL: socketSrv.URL, APIKey: "tk", Timeout: time.Second}),
				Timeout:   time.Second,
				OnFailure: "warn", // fail_mode: degraded
			},
			"osv": {
				Provider:  provider.NewOSVProvider(provider.OSVConfig{BaseURL: osvSrv.URL, Timeout: time.Second}),
				Timeout:   time.Second,
				OnFailure: "warn",
			},
		},
	})

	req := pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "lodash", Version: "4.17.20", Registry: "registry.npmjs.org"},
			{Name: "@acme/internal", Version: "1.0.0", Registry: "registry.npmjs.org"},
		},
	}

	findings, errs, skipped := o.CheckAllWithPrivacy(context.Background(), req)

	if len(skipped) != 1 {
		t.Errorf("want 1 skipped (@acme), got %d", len(skipped))
	}
	if skipped[0].Reason != pkgcheck.SkipReasonPrivateScopeDenylist {
		t.Errorf("want denylist reason, got %s", skipped[0].Reason)
	}

	ev := pkgcheck.NewEvaluator([]policy.PackageRule{
		{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
		{Match: policy.PackageMatch{}, Action: "allow"},
	})
	verdict := ev.EvaluateWithContext(pkgcheck.EvalContext{
		Findings:       findings,
		Ecosystem:      req.Ecosystem,
		ProviderErrors: errs,
		Skipped:        skipped,
	})

	if !strings.Contains(verdict.Summary, "degraded:") || !strings.Contains(verdict.Summary, "socket") {
		t.Errorf("verdict summary should be annotated degraded for socket, got %q", verdict.Summary)
	}
	if verdict.Action != pkgcheck.VerdictBlock {
		t.Errorf("OSV finding (critical) should drive verdict to block, got %s", verdict.Action)
	}
	if len(verdict.Skipped) != 1 {
		t.Errorf("verdict should carry 1 skipped, got %d", len(verdict.Skipped))
	}
}
