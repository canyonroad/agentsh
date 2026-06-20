package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/tor"
)

func TestApp_torGateway(t *testing.T) {
	pol, err := tor.New(config.ResolvedTorConfig{
		Enabled: true, Mode: tor.ModeAllow, SocksPorts: []int{9050},
		OnionRules: []config.TorOnionRule{{Onion: "*", Decision: "deny"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &App{torPolicy: pol}
	p, upstream, ports, ok := a.torGateway()
	if !ok || p == nil || upstream != "127.0.0.1:9050" || len(ports) != 1 {
		t.Fatalf("torGateway() = %v %q %v %v", p, upstream, ports, ok)
	}

	// Inactive when no policy.
	if _, _, _, ok := (&App{}).torGateway(); ok {
		t.Error("nil torPolicy must be inactive")
	}
}
