package tor

import (
	"net"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

func TestPolicyAdapter_ImplementsTorChecker(t *testing.T) {
	p, _ := New(config.ResolveTorConfig(config.TorConfig{}))
	var tc policy.TorChecker = &PolicyAdapter{Policy: p} // compile-time check
	v, ok := tc.EvalConnect(net.ParseIP("127.0.0.1"), 9050)
	if !ok || v.Vector != "socks_port" || v.Decision != "deny" {
		t.Fatalf("adapter EvalConnect wrong: ok=%v v=%+v", ok, v)
	}
}
