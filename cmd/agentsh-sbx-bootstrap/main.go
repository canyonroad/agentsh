// agentsh-sbx-bootstrap is the startup entrypoint installed into Docker
// Sandboxes by the AgentSH mixin kit. It merges the baked coding-agent
// policy with any user override, spawns the agentsh server, then probes
// the active enforcement tier and writes /run/agentsh/tier so the agent's
// SKILL.md can read it.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

const (
	defaultTemplatePath = "/usr/share/agentsh/coding-agent.template.yaml"
	defaultOverlayPath  = "/home/agent/.agentsh/policy.yaml"
	defaultPolicyPath   = "/etc/agentsh/policies/default.yaml"
	defaultTierPath     = "/run/agentsh/tier"
	// defaultBootstrapLog: target for the future bootstrap banner / tier probe
	// log. v1 writes those to stderr; the constant reserves the path so
	// installers, doc tooling, and Task 5 can reference a single source of truth.
	defaultBootstrapLog  = "/var/log/agentsh/bootstrap.log"
	defaultDaemonLog     = "/var/log/agentsh/daemon.log"
	defaultAgentshBin    = "/usr/bin/agentsh"
	defaultServerConfig  = "/etc/agentsh/config.yaml"
	defaultDaemonSocket  = "/run/agentsh/agentsh.sock"
	defaultSocketTimeout = 2 * time.Second
	defaultShimDir       = "/usr/lib/agentsh/shims"
)

func main() {
	var (
		tmpl       = flag.String("template", defaultTemplatePath, "Baked policy template path")
		overlay    = flag.String("overlay", defaultOverlayPath, "User override fragment path")
		policy     = flag.String("policy", defaultPolicyPath, "Output merged policy path")
		agentshBin = flag.String("agentsh", defaultAgentshBin, "Path to the agentsh binary")
		srvConfig  = flag.String("server-config", defaultServerConfig, "Path to the agentsh server config")
		sock       = flag.String("socket", defaultDaemonSocket, "Daemon socket path to poll for readiness")
		daemonLog  = flag.String("daemon-log", defaultDaemonLog, "Path to daemon log file")
	)
	flag.Parse()

	if err := mergeAndWritePolicy(*tmpl, *overlay, *policy); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: policy merge failed: %v\n", err)
		os.Exit(1)
	}

	if _, err := spawnDaemon(*agentshBin, []string{"server", "--config", *srvConfig}, *daemonLog); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: spawn daemon: %v\n", err)
		os.Exit(1)
	}

	if err := waitForSocket(*sock, defaultSocketTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: %v (continuing with degraded tier)\n", err)
		// Don't exit — tier probe will record tier=none.
	}

	shimDir := defaultShimDir
	if env := os.Getenv("AGENTSH_SHIM_DIR"); env != "" {
		shimDir = env
	}

	tier := "none"
	if ok, resolved, probeErr := probeShimTier(shimDir); probeErr != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: shim probe failed: %v\n", probeErr)
	} else if ok {
		tier = "shim"
		fmt.Fprintf(os.Stdout, "agentsh-sbx-bootstrap: shim tier active (curl -> %s)\n", resolved)
	} else {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: shim tier NOT active (PATH did not yield %s)\n", shimDir)
	}

	if err := writeTierFile(defaultTierPath, tier); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: write tier file: %v\n", err)
		os.Exit(1)
	}
}
