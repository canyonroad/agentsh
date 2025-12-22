package api

import (
	"github.com/agentsh/agentsh/internal/policy"
	"os"
	"path/filepath"
	"testing"

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
