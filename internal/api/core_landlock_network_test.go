//go:build linux

package api

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/capabilities"
	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

// TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig verifies that the
// seccompWrapperConfig JSON produced by setupSeccompWrapper reflects
// landlock.network.allow_connect_tcp / allow_bind_tcp values rather than
// hardcoded true/true.
func TestSetupSeccompWrapper_LandlockNetwork_HonorsConfig(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("seccomp wrapper only available on Linux")
	}
	if !capabilities.DetectLandlock().Available {
		t.Skip("Landlock not available on this host")
	}

	cases := []struct {
		name     string
		connect  bool
		bind     bool
		wantNet  bool
		wantBind bool
	}{
		{"both_true", true, true, true, true},
		{"connect_true_bind_false", true, false, true, false},
		{"connect_false_bind_false", false, false, false, false},
		{"connect_true_bind_true", true, true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := tc.connect
			bind := tc.bind

			enabled := true
			cfg := &config.Config{}
			cfg.Sandbox.UnixSockets.Enabled = &enabled
			cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
			cfg.Landlock.Enabled = true
			cfg.Landlock.Network.AllowConnectTCP = &connect
			cfg.Landlock.Network.AllowBindTCP = &bind

			app := newTestAppForSeccomp(t, cfg)
			req := types.ExecRequest{Command: "/bin/echo", Args: []string{"hi"}}
			sess := &session.Session{Workspace: "/tmp"}

			result := app.setupSeccompWrapper(req, "test-session", sess)
			if result == nil || result.extraCfg == nil {
				t.Fatal("expected non-nil wrapper setup result with extraCfg")
			}
			defer func() {
				if result.extraCfg.notifyParentSock != nil {
					result.extraCfg.notifyParentSock.Close()
				}
				for _, f := range result.extraCfg.extraFiles {
					if f != nil {
						f.Close()
					}
				}
			}()

			seccompJSON, ok := result.wrappedReq.Env["AGENTSH_SECCOMP_CONFIG"]
			if !ok {
				t.Fatal("AGENTSH_SECCOMP_CONFIG env var not set")
			}

			var parsed map[string]any
			if err := json.Unmarshal([]byte(seccompJSON), &parsed); err != nil {
				t.Fatalf("unmarshal seccomp config: %v\n%s", err, seccompJSON)
			}

			gotNet, _ := parsed["allow_network"].(bool)
			gotBind, _ := parsed["allow_bind"].(bool)
			if gotNet != tc.wantNet {
				t.Errorf("allow_network = %v; want %v (JSON: %s)", gotNet, tc.wantNet, seccompJSON)
			}
			if gotBind != tc.wantBind {
				t.Errorf("allow_bind = %v; want %v (JSON: %s)", gotBind, tc.wantBind, seccompJSON)
			}
		})
	}
}
