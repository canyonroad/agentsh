package api

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestChooseCommandTimeout_UsesPolicyWhenNoRequest(t *testing.T) {
	req := types.ExecRequest{}
	got := chooseCommandTimeout(req, 10*time.Second)
	if got != 10*time.Second {
		t.Fatalf("expected 10s, got %s", got)
	}
}

func TestChooseCommandTimeout_CapsRequestToPolicy(t *testing.T) {
	req := types.ExecRequest{Timeout: "20s"}
	got := chooseCommandTimeout(req, 10*time.Second)
	if got != 10*time.Second {
		t.Fatalf("expected 10s cap, got %s", got)
	}
}

func TestChooseCommandTimeout_AllowsSmallerRequest(t *testing.T) {
	req := types.ExecRequest{Timeout: "2s"}
	got := chooseCommandTimeout(req, 10*time.Second)
	if got != 2*time.Second {
		t.Fatalf("expected 2s, got %s", got)
	}
}

func TestChooseCommandTimeout_DefaultWhenNoPolicy(t *testing.T) {
	req := types.ExecRequest{}
	got := chooseCommandTimeout(req, 0)
	if got != defaultCommandTimeout {
		t.Fatalf("expected default %s, got %s", defaultCommandTimeout, got)
	}
}

