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
)

const (
	defaultTemplatePath = "/usr/share/agentsh/coding-agent.template.yaml"
	defaultOverlayPath  = "/home/agent/.agentsh/policy.yaml"
	defaultPolicyPath   = "/etc/agentsh/policies/default.yaml"
	defaultTierPath     = "/run/agentsh/tier"
)

func main() {
	var (
		tmpl    = flag.String("template", defaultTemplatePath, "Baked-in policy template path")
		overlay = flag.String("overlay", defaultOverlayPath, "User override fragment path (optional)")
		policy  = flag.String("policy", defaultPolicyPath, "Output merged policy path")
	)
	flag.Parse()

	if err := mergeAndWritePolicy(*tmpl, *overlay, *policy); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: policy merge failed: %v\n", err)
		os.Exit(1)
	}
	// Daemon spawn + tier probe land in Task 4 and Task 5.
}
