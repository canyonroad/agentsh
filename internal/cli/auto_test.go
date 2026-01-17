package cli

import "testing"

func TestAutoDisabled_FromEnv(t *testing.T) {
	t.Setenv("AGENTSH_NO_AUTO", "1")
	if !autoDisabled() {
		t.Fatalf("expected autoDisabled true")
	}
}

func TestShouldAutoStartServer_LoopbackDefaultPort(t *testing.T) {
	if !shouldAutoStartServer("http://127.0.0.1:18080") {
		t.Fatalf("expected loopback:18080 to be eligible for auto-start")
	}
	if shouldAutoStartServer("http://example.com:18080") {
		t.Fatalf("expected non-loopback to be ineligible for auto-start")
	}
	if shouldAutoStartServer("http://127.0.0.1:9090") {
		t.Fatalf("expected non-default port to be ineligible for auto-start")
	}
}
