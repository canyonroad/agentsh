package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
)

func TestMergeEnv_MarksInSession(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	out, _ := buildPolicyEnv(policy.ResolvedEnvPolicy{}, nil, sess, nil)
	got := map[string]string{}
	for _, kv := range out {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				got[kv[:i]] = kv[i+1:]
				break
			}
		}
	}

	if got["AGENTSH_IN_SESSION"] != "1" {
		t.Fatalf("expected AGENTSH_IN_SESSION=1, got %q", got["AGENTSH_IN_SESSION"])
	}
}

func TestMergeEnv_StripsHostSecrets(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	base := []string{
		"PATH=/usr/bin",
		"AWS_SECRET_ACCESS_KEY=sekret",
		"DOCKER_HOST=unix:///var/run/docker.sock",
		"TERM=xterm-256color",
	}

	pol := policy.ResolvedEnvPolicy{Deny: []string{"AWS_SECRET_ACCESS_KEY", "DOCKER_HOST"}, Allow: []string{"PATH", "TERM"}}
	gotMap := envSliceToMapMust(buildPolicyEnv(pol, base, sess, nil))

	if _, ok := gotMap["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Fatalf("expected AWS_SECRET_ACCESS_KEY to be stripped")
	}
	if _, ok := gotMap["DOCKER_HOST"]; ok {
		t.Fatalf("expected DOCKER_HOST to be stripped")
	}
	if gotMap["PATH"] == "" {
		t.Fatalf("expected PATH to be preserved")
	}
}

func TestMergeEnv_OverridesSecretStripped(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	overrides := map[string]string{
		"MY_SECRET": "topsecret",
		"SAFE":      "ok",
	}

	pol := policy.ResolvedEnvPolicy{Deny: []string{"MY_SECRET"}}
	gotMap := envSliceToMapMust(buildPolicyEnv(pol, nil, sess, overrides))

	if _, ok := gotMap["MY_SECRET"]; ok {
		t.Fatalf("expected MY_SECRET to be stripped from overrides")
	}
	if gotMap["SAFE"] != "ok" {
		t.Fatalf("expected SAFE to survive overrides")
	}
}

func TestMaybeAddShimEnv_AddsShimAndFlag(t *testing.T) {
	tmp := t.TempDir()
	shimPath := filepath.Join(tmp, "libenvshim.so")
	if err := os.WriteFile(shimPath, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Policies.EnvShimPath = shimPath
	in := []string{"PATH=/usr/bin"}
	out := maybeAddShimEnv(in, policy.ResolvedEnvPolicy{BlockIteration: true}, cfg)
	m := envSliceToMap(out)

	if m["AGENTSH_ENV_BLOCK_ITERATION"] != "1" {
		t.Fatalf("expected AGENTSH_ENV_BLOCK_ITERATION=1, got %q", m["AGENTSH_ENV_BLOCK_ITERATION"])
	}
	if got := m["LD_PRELOAD"]; got != shimPath {
		t.Fatalf("expected LD_PRELOAD to be shim path, got %q", got)
	}
}

func TestMaybeAddShimEnv_PrependsExistingLDPreload(t *testing.T) {
	tmp := t.TempDir()
	shimPath := filepath.Join(tmp, "libenvshim.so")
	if err := os.WriteFile(shimPath, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Policies.EnvShimPath = shimPath
	in := []string{"LD_PRELOAD=/other.so", "TERM=xterm"}
	out := maybeAddShimEnv(in, policy.ResolvedEnvPolicy{BlockIteration: true}, cfg)
	m := envSliceToMap(out)

	expected := shimPath + ":/other.so"
	if got := m["LD_PRELOAD"]; got != expected {
		t.Fatalf("expected LD_PRELOAD=%s, got %q", expected, got)
	}
}

func envSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				out[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return out
}

func envSliceToMapMust(env []string, err error) map[string]string {
	if err != nil {
		panic(err)
	}
	return envSliceToMap(env)
}

// TestBuildPolicyEnv_NetworkProxySetsHTTPProxy verifies that when the network proxy
// is set (via SetProxy), the HTTP_PROXY env vars are injected.
func TestBuildPolicyEnv_NetworkProxySetsHTTPProxy(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Set network proxy
	sess.SetProxy("http://127.0.0.1:8888", func() error { return nil })

	gotMap := envSliceToMapMust(buildPolicyEnv(policy.ResolvedEnvPolicy{}, nil, sess, nil))

	// HTTP_PROXY should be set
	if gotMap["HTTP_PROXY"] != "http://127.0.0.1:8888" {
		t.Errorf("expected HTTP_PROXY=http://127.0.0.1:8888, got %q", gotMap["HTTP_PROXY"])
	}
	if gotMap["HTTPS_PROXY"] != "http://127.0.0.1:8888" {
		t.Errorf("expected HTTPS_PROXY=http://127.0.0.1:8888, got %q", gotMap["HTTPS_PROXY"])
	}
	if gotMap["http_proxy"] != "http://127.0.0.1:8888" {
		t.Errorf("expected http_proxy=http://127.0.0.1:8888, got %q", gotMap["http_proxy"])
	}
}

// TestBuildPolicyEnv_LLMProxyDoesNotSetHTTPProxy verifies that when only the LLM proxy
// is set (via SetLLMProxy), the HTTP_PROXY env vars are NOT injected.
// This is a regression test for a bug where LLM proxy caused HTTP_PROXY to be set,
// which broke HTTPS CONNECT tunneling because the LLM proxy returns 400 for non-LLM requests.
func TestBuildPolicyEnv_LLMProxyDoesNotSetHTTPProxy(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Set only LLM proxy (not network proxy)
	sess.SetLLMProxy("http://127.0.0.1:9999", func() error { return nil })

	gotMap := envSliceToMapMust(buildPolicyEnv(policy.ResolvedEnvPolicy{}, nil, sess, nil))

	// HTTP_PROXY should NOT be set
	if _, ok := gotMap["HTTP_PROXY"]; ok {
		t.Errorf("expected HTTP_PROXY to NOT be set when only LLM proxy is configured, got %q", gotMap["HTTP_PROXY"])
	}
	if _, ok := gotMap["HTTPS_PROXY"]; ok {
		t.Errorf("expected HTTPS_PROXY to NOT be set when only LLM proxy is configured, got %q", gotMap["HTTPS_PROXY"])
	}

	// LLM env vars SHOULD be set
	if gotMap["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9999" {
		t.Errorf("expected ANTHROPIC_BASE_URL=http://127.0.0.1:9999, got %q", gotMap["ANTHROPIC_BASE_URL"])
	}
	if gotMap["OPENAI_BASE_URL"] != "http://127.0.0.1:9999" {
		t.Errorf("expected OPENAI_BASE_URL=http://127.0.0.1:9999, got %q", gotMap["OPENAI_BASE_URL"])
	}
}

// TestBuildPolicyEnv_BothProxiesSetIndependently verifies that network proxy and LLM proxy
// can be configured independently, with network proxy setting HTTP_PROXY and LLM proxy
// setting ANTHROPIC_BASE_URL/OPENAI_BASE_URL.
func TestBuildPolicyEnv_BothProxiesSetIndependently(t *testing.T) {
	sessions := session.NewManager(10)
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	// Set both proxies with different URLs
	sess.SetProxy("http://127.0.0.1:8080", func() error { return nil })     // Network proxy
	sess.SetLLMProxy("http://127.0.0.1:9090", func() error { return nil })  // LLM proxy

	gotMap := envSliceToMapMust(buildPolicyEnv(policy.ResolvedEnvPolicy{}, nil, sess, nil))

	// HTTP_PROXY should be set to network proxy
	if gotMap["HTTP_PROXY"] != "http://127.0.0.1:8080" {
		t.Errorf("expected HTTP_PROXY=http://127.0.0.1:8080, got %q", gotMap["HTTP_PROXY"])
	}

	// LLM env vars should be set to LLM proxy (different URL)
	if gotMap["ANTHROPIC_BASE_URL"] != "http://127.0.0.1:9090" {
		t.Errorf("expected ANTHROPIC_BASE_URL=http://127.0.0.1:9090, got %q", gotMap["ANTHROPIC_BASE_URL"])
	}
	if gotMap["OPENAI_BASE_URL"] != "http://127.0.0.1:9090" {
		t.Errorf("expected OPENAI_BASE_URL=http://127.0.0.1:9090, got %q", gotMap["OPENAI_BASE_URL"])
	}
}

func TestMergeEnvInject(t *testing.T) {
	tests := []struct {
		name       string
		cfgEnv     map[string]string
		polEnv     map[string]string
		wantResult map[string]string
	}{
		{
			name:       "both_nil",
			cfgEnv:     nil,
			polEnv:     nil,
			wantResult: map[string]string{},
		},
		{
			name:       "config_only",
			cfgEnv:     map[string]string{"BASH_ENV": "/global/path"},
			polEnv:     nil,
			wantResult: map[string]string{"BASH_ENV": "/global/path"},
		},
		{
			name:       "policy_only",
			cfgEnv:     nil,
			polEnv:     map[string]string{"BASH_ENV": "/policy/path"},
			wantResult: map[string]string{"BASH_ENV": "/policy/path"},
		},
		{
			name:       "policy_wins_conflict",
			cfgEnv:     map[string]string{"BASH_ENV": "/global/path", "EXTRA": "global"},
			polEnv:     map[string]string{"BASH_ENV": "/policy/path"},
			wantResult: map[string]string{"BASH_ENV": "/policy/path", "EXTRA": "global"},
		},
		{
			name:       "merge_disjoint",
			cfgEnv:     map[string]string{"GLOBAL_VAR": "a"},
			polEnv:     map[string]string{"POLICY_VAR": "b"},
			wantResult: map[string]string{"GLOBAL_VAR": "a", "POLICY_VAR": "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Sandbox.EnvInject = tt.cfgEnv

			var pol *policy.Engine
			if tt.polEnv != nil {
				p := &policy.Policy{
					Version:   1,
					Name:      "test",
					EnvInject: tt.polEnv,
				}
				var err error
				pol, err = policy.NewEngine(p, false)
				if err != nil {
					t.Fatal(err)
				}
			}

			got := mergeEnvInject(cfg, pol)
			if len(got) != len(tt.wantResult) {
				t.Errorf("mergeEnvInject() returned %d keys, want %d", len(got), len(tt.wantResult))
			}
			for k, v := range tt.wantResult {
				if got[k] != v {
					t.Errorf("mergeEnvInject()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestMergeEnvInject_NilConfig(t *testing.T) {
	// Test with nil config
	p := &policy.Policy{
		Version:   1,
		Name:      "test",
		EnvInject: map[string]string{"BASH_ENV": "/policy/path"},
	}
	pol, err := policy.NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	got := mergeEnvInject(nil, pol)
	if len(got) != 1 {
		t.Errorf("mergeEnvInject(nil, pol) returned %d keys, want 1", len(got))
	}
	if got["BASH_ENV"] != "/policy/path" {
		t.Errorf("mergeEnvInject(nil, pol)[BASH_ENV] = %q, want %q", got["BASH_ENV"], "/policy/path")
	}

	// Test with both nil
	got2 := mergeEnvInject(nil, nil)
	if len(got2) != 0 {
		t.Errorf("mergeEnvInject(nil, nil) returned %d keys, want 0", len(got2))
	}
}
