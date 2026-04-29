package config

import (
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
)

func TestResolveBlockedFamilies(t *testing.T) {
	in := []SandboxSeccompSocketFamilyConfig{
		{Family: "AF_ALG", Action: "errno"},
		{Family: "40", Action: "kill"},
		{Family: "AF_VSOCK", Action: ""}, // empty action → defaults to errno
	}
	out, err := ResolveBlockedFamilies(in)
	if err != nil {
		t.Fatalf("ResolveBlockedFamilies: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d entries, want 3", len(out))
	}
	if out[0].Family != 38 || out[0].Name != "AF_ALG" || out[0].Action != seccomp.OnBlockErrno {
		t.Errorf("entry 0 wrong: %+v", out[0])
	}
	if out[1].Family != 40 || out[1].Name != "" || out[1].Action != seccomp.OnBlockKill {
		t.Errorf("entry 1 wrong: %+v", out[1])
	}
	if out[2].Action != seccomp.OnBlockErrno {
		t.Errorf("entry 2 default action wrong: %s", out[2].Action)
	}
}

func TestResolveBlockedFamilies_RejectsBadEntry(t *testing.T) {
	in := []SandboxSeccompSocketFamilyConfig{
		{Family: "BOGUS", Action: "errno"},
	}
	_, err := ResolveBlockedFamilies(in)
	if err == nil {
		t.Errorf("expected error for bogus family name")
	}
}
