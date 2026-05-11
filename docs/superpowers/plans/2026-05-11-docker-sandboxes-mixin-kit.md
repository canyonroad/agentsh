# Docker Sandboxes Mixin Kit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Docker Sandboxes mixin kit at `docker/sbx-kit/` that installs AgentSH into any sandbox at creation and routes the agent's command-level activity through a coding-agent-tuned policy. Invoked via `sbx run <agent> --kit git+https://github.com/erans/agentsh.git#dir=docker/sbx-kit`.

**Architecture:** A `schemaVersion: "1"` mixin kit (`spec.yaml` + `files/` tree) runs a one-shot `install` that curls a new `install.sh` from the latest GitHub release; `initFiles` injects PATH precedence files; the `startup` command runs a new `agentsh-sbx-bootstrap` binary that merges the baked coding-agent policy template with any user-supplied override into `/etc/agentsh/policies/default.yaml`, spawns `agentsh server`, then probes the shim enforcement tier and writes `/run/agentsh/tier`. v1 ships the shim tier only; LD_PRELOAD and ptrace tiers are parked behind forward-compatible tier labels.

**Tech Stack:** Go (existing AgentSH stack), gopkg.in/yaml.v3, cobra, GoReleaser/nfpm for packaging, GitHub Actions for the release pipeline, Bash for the installer + smoke test, Docker Sandboxes `spec.yaml` schema v1.

**Spec reference:** `docs/superpowers/specs/2026-05-11-docker-sandboxes-mixin-kit-design.md`.

---

## Task 1: Coding-agent policy template

**Files:**
- Create: `configs/policies/coding-agent.yaml`
- Test: `internal/policy/coding_agent_template_test.go`

This task delivers the baked-in policy from spec §8. It validates by parsing through the existing `policy.LoadFromBytes()` loader, so any field-name typo fails the test immediately.

- [ ] **Step 1: Write the failing validation test**

Create `internal/policy/coding_agent_template_test.go`:

```go
package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCodingAgentTemplate_Loads verifies the policy that the Docker Sandboxes
// mixin kit bakes into /etc/agentsh/policies/default.yaml parses cleanly
// through the canonical loader. Any field-name typo or schema drift will be
// caught here before the kit ships.
func TestCodingAgentTemplate_Loads(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "policies", "coding-agent.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	p, err := LoadFromBytes(data)
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	if p.Name != "coding-agent" {
		t.Errorf("Name = %q, want %q", p.Name, "coding-agent")
	}
	if len(p.FileRules) == 0 {
		t.Error("expected file_rules")
	}
	if len(p.CommandRules) == 0 {
		t.Error("expected command_rules")
	}
	if len(p.SignalRules) == 0 {
		t.Error("expected signal_rules")
	}
}

// TestCodingAgentTemplate_DeniesCredentialPaths spot-checks that the rules from
// the design spec are actually present. Coverage isn't exhaustive; this just
// catches accidental rule deletion during future edits.
func TestCodingAgentTemplate_DeniesCredentialPaths(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "policies", "coding-agent.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"/.ssh/",
		"/.aws/",
		"/.gnupg/",
		"/.kube/",
		"/.netrc",
		"/etc/agentsh/",
		"/usr/lib/agentsh/",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected coding-agent.yaml to reference %q", want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy -run TestCodingAgentTemplate_ -v`
Expected: FAIL — `configs/policies/coding-agent.yaml` does not exist.

- [ ] **Step 3: Create the coding-agent policy**

Create `configs/policies/coding-agent.yaml`:

```yaml
# Coding-agent policy for AgentSH inside Docker Sandboxes.
# This is the baked-in template the agentsh-sbx-bootstrap binary merges with
# any user override at /home/agent/.agentsh/policy.yaml on every sandbox start.
#
# Reference: /usr/share/doc/agentsh/policy-reference.md
# To extend: write rules to /home/agent/.agentsh/policy.yaml; the bootstrap
# merges them on top of this file (user wins on name collision; otherwise
# rules concatenate in declared order).

version: 1
name: coding-agent
description: |
  Default policy for AI coding agents (Claude Code, OpenCode, Gemini CLI)
  running inside Docker Sandboxes. Tuned for path/command granularity inside
  the sandbox; outbound network controls are handled by the Docker Sandbox
  proxy and intentionally not duplicated here.

# =============================================================================
# FILE RULES — evaluated in order, first match wins.
# =============================================================================
file_rules:

  # ---- Sensitive credential paths: deny before any allow-home rule matches.
  - name: deny-credential-paths
    description: Block reads/writes of host credentials that may have leaked into the sandbox.
    paths:
      - "/home/**/.ssh/**"
      - "/home/**/.aws/**"
      - "/home/**/.gnupg/**"
      - "/home/**/.kube/**"
      - "/home/**/.docker/config.json"
      - "/home/**/.netrc"
      - "/home/**/.config/gcloud/**"
      - "/home/**/.config/gh/**"
      - "/home/**/.config/git-credentials"
      - "/root/.ssh/**"
      - "/root/.aws/**"
      - "/root/.gnupg/**"
      - "/root/.kube/**"
      - "/root/.netrc"
    operations: ["*"]
    decision: deny
    message: "Access to credential path {{.Path}} is denied by the coding-agent policy."

  # ---- AgentSH self-protection: agent cannot edit its own policy/logs/binaries.
  - name: deny-self-write
    description: Prevent the agent from tampering with AgentSH state.
    paths:
      - "/etc/agentsh/**"
      - "/usr/lib/agentsh/**"
      - "/usr/share/agentsh/**"
      - "/run/agentsh/**"
      - "/var/lib/agentsh/**"
      - "/var/log/agentsh/**"
    operations: [write, create, mkdir, chmod, rename, delete, rmdir]
    decision: deny
    message: "Write to AgentSH-controlled path {{.Path}} is denied."

  # ---- Workspace: full read/write; deletes are soft so rm -rf is recoverable.
  - name: allow-workspace-read
    paths: ["/workspace", "/workspace/**"]
    operations: [read, open, stat, list, readlink]
    decision: allow

  - name: allow-workspace-write
    paths: ["/workspace", "/workspace/**"]
    operations: [write, create, mkdir, chmod, rename]
    decision: allow

  - name: soft-delete-workspace
    description: Soft-delete workspace files (recoverable via /var/lib/agentsh/trash).
    paths: ["/workspace", "/workspace/**"]
    operations: [delete, rmdir]
    decision: soft_delete
    message: "File quarantined (recoverable): {{.Path}}"

  # ---- Home: read/write everywhere except the credential paths denied above.
  - name: allow-home
    paths: ["/home/**", "/root/**"]
    operations: ["*"]
    decision: allow

  # ---- Package manager caches: full allow (routine for coding work).
  - name: allow-package-caches
    paths:
      - "/home/**/.npm/**"
      - "/home/**/.cache/pip/**"
      - "/home/**/.cargo/**"
      - "/home/**/.cache/go-build/**"
      - "/home/**/.rustup/**"
      - "/home/**/.gradle/caches/**"
      - "/home/**/.m2/**"
      - "/root/.npm/**"
      - "/root/.cache/pip/**"
      - "/root/.cargo/**"
    operations: ["*"]
    decision: allow

  # ---- Tmp: full access.
  - name: allow-tmp
    paths: ["/tmp/**", "/var/tmp/**"]
    operations: ["*"]
    decision: allow

  # ---- System paths: read-only allow.
  - name: allow-system-read
    paths:
      - "/usr/**"
      - "/lib/**"
      - "/lib64/**"
      - "/bin/**"
      - "/sbin/**"
      - "/opt/**"
    operations: [read, open, stat, list, readlink]
    decision: allow

  - name: allow-etc-read-safe
    paths:
      - "/etc/hosts"
      - "/etc/resolv.conf"
      - "/etc/ssl/**"
      - "/etc/ca-certificates/**"
      - "/etc/localtime"
      - "/etc/timezone"
      - "/etc/mime.types"
      - "/etc/protocols"
      - "/etc/services"
      - "/etc/environment"
      - "/etc/environment.d/**"
      - "/etc/profile.d/**"
    operations: [read, open, stat]
    decision: allow

# =============================================================================
# COMMAND RULES
# =============================================================================
command_rules:

  - name: deny-privilege-escalation
    description: The Docker Sandbox already pins the agent to a fixed user; escalation is suspicious.
    commands: [sudo, su, doas]
    decision: deny
    message: "Privilege escalation via {{.Command}} is denied inside a Docker Sandbox."

  - name: audit-curl-pipe-to-shell
    description: Audit curl/wget piped to sh/bash. v1.1 will replace this with redirect to agentsh-fetch.
    commands: [curl, wget]
    args_patterns:
      - ".*\\|\\s*(sh|bash|zsh).*"
    decision: audit
    message: "curl|sh pattern detected: {{.Command}} {{.Args}}"

  - name: approve-recursive-chmod
    description: Require approval for chmod -R on / or /home, or chmod 777.
    commands: [chmod]
    args_patterns:
      - "^-R\\s+/$"
      - "^-R\\s+/home.*"
      - ".*777.*"
    decision: approve
    message: "Recursive or world-writable chmod requested: chmod {{.Args}}"
    timeout: 5m

  - name: allow-package-installers
    description: Routine for coding agents; allow with audit.
    commands: [pip, pip3, npm, yarn, pnpm, cargo, apt, apt-get, gem, bundle]
    decision: allow

# =============================================================================
# SIGNAL RULES
# =============================================================================
signal_rules:

  - name: deny-signal-pid1
    description: The agent must not signal PID 1.
    signals: ["@fatal", "@job"]
    target:
      type: pid_range
      min: 1
      max: 1
    decision: deny
    message: "Signaling PID 1 is denied."

  - name: deny-signal-agentsh
    description: The agent must not signal AgentSH processes.
    signals: ["@fatal"]
    target:
      type: external
      pattern: "agentsh*"
    decision: deny
    message: "Signaling AgentSH is denied."

  - name: allow-signal-own-tree
    description: Allow signals within the agent's own subprocess tree.
    signals: ["@fatal", "@job"]
    target:
      type: children
    decision: allow

# =============================================================================
# AUDIT
# =============================================================================
audit:
  log_allowed: false
  log_denied: true
  log_approved: true
  retention_days: 7
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy -run TestCodingAgentTemplate_ -v`
Expected: PASS.

- [ ] **Step 5: Run the full policy package test suite to confirm no regressions**

Run: `go test ./internal/policy/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add configs/policies/coding-agent.yaml internal/policy/coding_agent_template_test.go
git commit -m "policy: add coding-agent template baked into the Docker Sandboxes mixin kit"
```

---

## Task 2: Policy merge helper

**Files:**
- Create: `internal/policy/merge.go`
- Test: `internal/policy/merge_test.go`

The bootstrap binary needs to merge the baked template with the user-supplied override fragment. Semantics: user wins on rule-name collisions; otherwise rules concatenate in declared order. Keep the merge contained to a new file so the existing loader is unchanged.

- [ ] **Step 1: Write the failing test**

Create `internal/policy/merge_test.go`:

```go
package policy

import (
	"testing"
)

func TestMergeOverlay_OverlayWinsOnNameCollision(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "base",
		FileRules: []FileRule{
			{Name: "rule-a", Decision: "allow", Paths: []string{"/a"}},
			{Name: "rule-b", Decision: "allow", Paths: []string{"/b"}},
		},
	}
	overlay := &Policy{
		Version: 1,
		Name:    "overlay",
		FileRules: []FileRule{
			{Name: "rule-b", Decision: "deny", Paths: []string{"/b"}},
			{Name: "rule-c", Decision: "allow", Paths: []string{"/c"}},
		},
	}

	merged := MergeOverlay(base, overlay)

	if got := len(merged.FileRules); got != 3 {
		t.Fatalf("len(FileRules) = %d, want 3", got)
	}
	if merged.FileRules[0].Name != "rule-a" {
		t.Errorf("FileRules[0].Name = %q, want rule-a", merged.FileRules[0].Name)
	}
	if merged.FileRules[1].Name != "rule-b" || merged.FileRules[1].Decision != "deny" {
		t.Errorf("FileRules[1] = %+v, want rule-b with decision=deny (overlay wins)", merged.FileRules[1])
	}
	if merged.FileRules[2].Name != "rule-c" {
		t.Errorf("FileRules[2].Name = %q, want rule-c", merged.FileRules[2].Name)
	}
}

func TestMergeOverlay_NilOverlayReturnsBase(t *testing.T) {
	base := &Policy{Version: 1, Name: "base", FileRules: []FileRule{{Name: "x"}}}
	merged := MergeOverlay(base, nil)
	if merged != base {
		t.Errorf("MergeOverlay(base, nil) should return base unchanged")
	}
}

func TestMergeOverlay_NilBaseReturnsOverlay(t *testing.T) {
	overlay := &Policy{Version: 1, Name: "overlay", FileRules: []FileRule{{Name: "x"}}}
	merged := MergeOverlay(nil, overlay)
	if merged != overlay {
		t.Errorf("MergeOverlay(nil, overlay) should return overlay unchanged")
	}
}

func TestMergeOverlay_PreservesAllRuleKinds(t *testing.T) {
	base := &Policy{
		Version:      1,
		Name:         "base",
		FileRules:    []FileRule{{Name: "f1"}},
		CommandRules: []CommandRule{{Name: "c1"}},
		SignalRules:  []SignalRule{{Name: "s1"}},
		NetworkRules: []NetworkRule{{Name: "n1"}},
	}
	overlay := &Policy{
		Version:      1,
		Name:         "overlay",
		FileRules:    []FileRule{{Name: "f2"}},
		CommandRules: []CommandRule{{Name: "c2"}},
		SignalRules:  []SignalRule{{Name: "s2"}},
		NetworkRules: []NetworkRule{{Name: "n2"}},
	}
	merged := MergeOverlay(base, overlay)
	if len(merged.FileRules) != 2 || len(merged.CommandRules) != 2 ||
		len(merged.SignalRules) != 2 || len(merged.NetworkRules) != 2 {
		t.Errorf("merged rule counts wrong: %+v", merged)
	}
}

func TestMergeOverlay_KeepsBaseMetadata(t *testing.T) {
	base := &Policy{Version: 1, Name: "base", Description: "from base"}
	overlay := &Policy{Version: 1, Name: "overlay"}
	merged := MergeOverlay(base, overlay)
	if merged.Name != "base" {
		t.Errorf("merged.Name = %q, want %q (base metadata preserved)", merged.Name, "base")
	}
	if merged.Description != "from base" {
		t.Errorf("merged.Description = %q, want %q", merged.Description, "from base")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy -run TestMergeOverlay -v`
Expected: FAIL — `MergeOverlay` is undefined.

- [ ] **Step 3: Implement the merge helper**

Create `internal/policy/merge.go`:

```go
package policy

// MergeOverlay returns a new Policy formed by overlaying `overlay` rules on
// top of `base`. Rules with matching names in overlay replace base entries
// in-place; other overlay rules are appended in declared order. Base metadata
// (Version, Name, Description, ResourceLimits, EnvPolicy, Audit) is
// preserved from base; overlay metadata is ignored.
//
// If either argument is nil, the other is returned unchanged. This lets
// callers handle "no user override" without a nil check at the call site.
//
// Used by cmd/agentsh-sbx-bootstrap to combine the baked coding-agent
// template with /home/agent/.agentsh/policy.yaml at sandbox startup.
func MergeOverlay(base, overlay *Policy) *Policy {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	out := *base
	out.FileRules = mergeFileRules(base.FileRules, overlay.FileRules)
	out.NetworkRules = mergeNetworkRules(base.NetworkRules, overlay.NetworkRules)
	out.CommandRules = mergeCommandRules(base.CommandRules, overlay.CommandRules)
	out.UnixRules = mergeUnixRules(base.UnixRules, overlay.UnixRules)
	out.SignalRules = mergeSignalRules(base.SignalRules, overlay.SignalRules)
	return &out
}

func mergeFileRules(base, overlay []FileRule) []FileRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]FileRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeNetworkRules(base, overlay []NetworkRule) []NetworkRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]NetworkRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeCommandRules(base, overlay []CommandRule) []CommandRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]CommandRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeUnixRules(base, overlay []UnixSocketRule) []UnixSocketRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]UnixSocketRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}

func mergeSignalRules(base, overlay []SignalRule) []SignalRule {
	if len(overlay) == 0 {
		return base
	}
	idx := map[string]int{}
	for i, r := range base {
		idx[r.Name] = i
	}
	out := append([]SignalRule(nil), base...)
	for _, r := range overlay {
		if i, ok := idx[r.Name]; ok && r.Name != "" {
			out[i] = r
			continue
		}
		out = append(out, r)
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy -run TestMergeOverlay -v`
Expected: PASS — all five test functions.

- [ ] **Step 5: Run the full policy package**

Run: `go test ./internal/policy/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/merge.go internal/policy/merge_test.go
git commit -m "policy: add MergeOverlay helper for sbx bootstrap policy stacking"
```

---

## Task 3: Bootstrap binary — policy merge + write

**Files:**
- Create: `cmd/agentsh-sbx-bootstrap/main.go`
- Create: `cmd/agentsh-sbx-bootstrap/policy.go`
- Test: `cmd/agentsh-sbx-bootstrap/policy_test.go`

The bootstrap binary is the brains of the kit's `startup` phase. This task lands only the policy-merge step in isolation so we can TDD it without conflating it with daemon launch and probing (later tasks).

The merge step's job: read `/usr/share/agentsh/coding-agent.template.yaml`, read `/home/agent/.agentsh/policy.yaml` if present and parseable, merge via `policy.MergeOverlay`, write the result atomically to `/etc/agentsh/policies/default.yaml`. On any failure, fall back to writing just the bare template — never leave the file half-written.

- [ ] **Step 1: Write the failing test**

Create `cmd/agentsh-sbx-bootstrap/policy_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseTemplate = `
version: 1
name: coding-agent
file_rules:
  - name: allow-tmp
    paths: ["/tmp/**"]
    operations: ["*"]
    decision: allow
`

func TestMergeAndWritePolicy_NoOverlay(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, overlay, out); err != nil {
		t.Fatalf("mergeAndWritePolicy: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "allow-tmp") {
		t.Errorf("expected output to contain base rules; got: %s", got)
	}
}

func TestMergeAndWritePolicy_WithOverlay(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	overlayBody := `
version: 1
name: user-overlay
file_rules:
  - name: allow-extra
    paths: ["/data/**"]
    operations: ["*"]
    decision: allow
`
	if err := os.WriteFile(overlay, []byte(overlayBody), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, overlay, out); err != nil {
		t.Fatalf("mergeAndWritePolicy: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "allow-tmp") {
		t.Error("expected base rule allow-tmp in merged output")
	}
	if !strings.Contains(body, "allow-extra") {
		t.Error("expected overlay rule allow-extra in merged output")
	}
}

func TestMergeAndWritePolicy_BadOverlayFallsBackToTemplate(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, []byte("not: [valid: yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, overlay, out); err != nil {
		t.Fatalf("mergeAndWritePolicy should not error on bad overlay: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "allow-tmp") {
		t.Error("expected fallback to template-only on bad overlay")
	}
}

func TestMergeAndWritePolicy_MissingTemplateErrors(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "nonexistent.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	err := mergeAndWritePolicy(tmpl, overlay, out)
	if err == nil {
		t.Fatal("expected error when template is missing")
	}
}

func TestMergeAndWritePolicy_AtomicWrite(t *testing.T) {
	// If the destination already exists with content X, and the merge succeeds,
	// the file should contain the new content (i.e. rename, not append).
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("stale: content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, "", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "stale") {
		t.Error("expected stale content to be replaced")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/agentsh-sbx-bootstrap/... -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Create the `main.go` skeleton**

Create `cmd/agentsh-sbx-bootstrap/main.go`:

```go
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
```

- [ ] **Step 4: Implement `mergeAndWritePolicy`**

Create `cmd/agentsh-sbx-bootstrap/policy.go`:

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/policy"
	"gopkg.in/yaml.v3"
)

// mergeAndWritePolicy reads the baked template at `tmpl`, reads the optional
// user override at `overlay` (any read or parse failure is logged to stderr
// and treated as "no overlay"), merges them via policy.MergeOverlay, and
// writes the result atomically to `out` via a temp file + rename.
//
// Returns an error only when the template itself cannot be read or parsed.
// A missing/broken overlay is intentionally non-fatal: the template alone is
// always a safe fallback and the bootstrap is required to fail-open.
func mergeAndWritePolicy(tmpl, overlay, out string) error {
	tmplBytes, err := os.ReadFile(tmpl)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	base, err := policy.LoadFromBytes(tmplBytes)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	var ov *policy.Policy
	if overlay != "" {
		ovBytes, ovErr := os.ReadFile(overlay)
		switch {
		case os.IsNotExist(ovErr):
			// No override file: fine. Bare template wins.
		case ovErr != nil:
			fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: read overlay %q: %v (falling back to template only)\n", overlay, ovErr)
		default:
			parsed, pErr := policy.LoadFromBytes(ovBytes)
			if pErr != nil {
				fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: parse overlay %q: %v (falling back to template only)\n", overlay, pErr)
			} else {
				ov = parsed
			}
		}
	}

	merged := policy.MergeOverlay(base, ov)

	mergedYAML, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged policy: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, mergedYAML, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, out); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./cmd/agentsh-sbx-bootstrap/... -v`
Expected: PASS — all five test functions.

- [ ] **Step 6: Build the binary**

Run: `go build ./cmd/agentsh-sbx-bootstrap`
Expected: success, binary created in cwd.

- [ ] **Step 7: Commit**

```bash
git add cmd/agentsh-sbx-bootstrap/main.go cmd/agentsh-sbx-bootstrap/policy.go cmd/agentsh-sbx-bootstrap/policy_test.go
git commit -m "bootstrap: cmd/agentsh-sbx-bootstrap with policy merge step"
```

---

## Task 4: Bootstrap binary — daemon spawn + socket wait

**Files:**
- Create: `cmd/agentsh-sbx-bootstrap/daemon.go`
- Test: `cmd/agentsh-sbx-bootstrap/daemon_test.go`
- Modify: `cmd/agentsh-sbx-bootstrap/main.go`

This task adds the daemon-spawn step to the bootstrap. It fork-execs `agentsh server --config /etc/agentsh/config.yaml` in the background and waits up to 2s for the daemon's Unix socket to appear. On timeout, the bootstrap logs to `/var/log/agentsh/bootstrap.log` and continues — the tier probe (next task) will record `tier=none` if the socket is absent.

The daemon spawn is tested with a fake `agentsh` binary in the test's PATH that just touches the socket path. That keeps the test hermetic and avoids depending on the real `agentsh server` startup time.

- [ ] **Step 1: Write the failing test**

Create `cmd/agentsh-sbx-bootstrap/daemon_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSpawnDaemonAndWait_SocketAppears(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets only")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "agentsh.sock")

	// Fake "daemon": a shell script that writes the socket file after a small
	// delay. The bootstrap should observe it within the 2s window.
	fakeBin := filepath.Join(dir, "fake-agentsh")
	script := "#!/bin/sh\n(sleep 0.1; touch " + sock + ") &\nexec sleep 5\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, "bootstrap.log")
	cmd, err := spawnDaemon(fakeBin, []string{"server"}, logPath)
	if err != nil {
		t.Fatalf("spawnDaemon: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	if err := waitForSocket(sock, 2*time.Second); err != nil {
		t.Fatalf("waitForSocket: %v", err)
	}
}

func TestWaitForSocket_TimesOut(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "nope.sock")
	start := time.Now()
	err := waitForSocket(sock, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("waitForSocket overshot deadline: %v", elapsed)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-sbx-bootstrap/... -run TestSpawnDaemonAndWait -v`
Expected: FAIL — `spawnDaemon` and `waitForSocket` are undefined.

- [ ] **Step 3: Implement daemon spawn + socket wait**

Create `cmd/agentsh-sbx-bootstrap/daemon.go`:

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// spawnDaemon fork-execs `bin args...` with stdout/stderr appended to logPath.
// The child is detached; the returned *exec.Cmd lets the caller signal it if
// needed (in normal flow the bootstrap exits after probing and the daemon
// keeps running, reparented to PID 1).
func spawnDaemon(bin string, args []string, logPath string) (*exec.Cmd, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir log dir: %w", err)
	}
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		logF.Close()
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}
	// Release the parent's reference to the log file FD once exec(2) has dup'd
	// stdio. The child keeps its own dup'd FD.
	go func() { _ = logF.Close() }()
	return cmd, nil
}

// waitForSocket polls for a filesystem entry at sockPath, returning nil as
// soon as it exists. Returns an error if the deadline elapses first.
//
// We check existence rather than `Dial` because the daemon may use a
// different socket type (gRPC vs HTTP) and a successful Dial isn't required
// to confirm "the daemon has started writing its socket" — only that the
// file exists.
func waitForSocket(sockPath string, deadline time.Duration) error {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if _, err := os.Stat(sockPath); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("socket %q did not appear within %s", sockPath, deadline)
}
```

- [ ] **Step 4: Wire it into `main.go`**

Replace `cmd/agentsh-sbx-bootstrap/main.go` with:

```go
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
	defaultTemplatePath  = "/usr/share/agentsh/coding-agent.template.yaml"
	defaultOverlayPath   = "/home/agent/.agentsh/policy.yaml"
	defaultPolicyPath    = "/etc/agentsh/policies/default.yaml"
	defaultTierPath      = "/run/agentsh/tier"
	defaultBootstrapLog  = "/var/log/agentsh/bootstrap.log"
	defaultDaemonLog     = "/var/log/agentsh/daemon.log"
	defaultAgentshBin    = "/usr/bin/agentsh"
	defaultServerConfig  = "/etc/agentsh/config.yaml"
	defaultDaemonSocket  = "/run/agentsh/agentsh.sock"
	defaultSocketTimeout = 2 * time.Second
)

func main() {
	var (
		tmpl       = flag.String("template", defaultTemplatePath, "Baked policy template path")
		overlay    = flag.String("overlay", defaultOverlayPath, "User override fragment path")
		policy     = flag.String("policy", defaultPolicyPath, "Output merged policy path")
		agentshBin = flag.String("agentsh", defaultAgentshBin, "Path to the agentsh binary")
		srvConfig  = flag.String("server-config", defaultServerConfig, "Path to the agentsh server config")
		sock       = flag.String("socket", defaultDaemonSocket, "Daemon socket path to poll for readiness")
	)
	flag.Parse()

	if err := mergeAndWritePolicy(*tmpl, *overlay, *policy); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: policy merge failed: %v\n", err)
		os.Exit(1)
	}

	if _, err := spawnDaemon(*agentshBin, []string{"server", "--config", *srvConfig}, defaultDaemonLog); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: spawn daemon: %v\n", err)
		os.Exit(1)
	}

	if err := waitForSocket(*sock, defaultSocketTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "agentsh-sbx-bootstrap: %v (continuing with degraded tier)\n", err)
		// Don't exit — tier probe will record tier=none.
	}

	// Tier probe lands in Task 5.
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./cmd/agentsh-sbx-bootstrap/... -v`
Expected: PASS — all merge tests plus the two new daemon tests.

- [ ] **Step 6: Build to verify the package still compiles**

Run: `go build ./cmd/agentsh-sbx-bootstrap`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add cmd/agentsh-sbx-bootstrap/daemon.go cmd/agentsh-sbx-bootstrap/daemon_test.go cmd/agentsh-sbx-bootstrap/main.go
git commit -m "bootstrap: spawn agentsh server and wait for socket"
```

---

## Task 5: Bootstrap binary — tier-1 (shim) probe and tier file

**Files:**
- Create: `cmd/agentsh-sbx-bootstrap/tier.go`
- Test: `cmd/agentsh-sbx-bootstrap/tier_test.go`
- Modify: `cmd/agentsh-sbx-bootstrap/main.go`

This task adds the shim-tier probe. The probe spawns `/bin/sh -c 'command -v curl'` and checks the resolved path starts with the shim directory. The active tier (`shim` or `none`) is written to `/run/agentsh/tier`.

- [ ] **Step 1: Write the failing test**

Create `cmd/agentsh-sbx-bootstrap/tier_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProbeShimTier_DetectsShimOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based probe is POSIX only")
	}
	dir := t.TempDir()
	shimDir := filepath.Join(dir, "shims")
	if err := os.Mkdir(shimDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Place a fake `curl` executable in the shim dir.
	fakeCurl := filepath.Join(shimDir, "curl")
	if err := os.WriteFile(fakeCurl, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Inject the shim dir at the front of PATH for the probe.
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	ok, resolved, err := probeShimTier(shimDir)
	if err != nil {
		t.Fatalf("probeShimTier: %v", err)
	}
	if !ok {
		t.Errorf("expected probe to detect shim; resolved=%q", resolved)
	}
	if !strings.HasPrefix(resolved, shimDir) {
		t.Errorf("resolved %q should be under shim dir %q", resolved, shimDir)
	}
}

func TestProbeShimTier_RejectsRealCurl(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-based probe is POSIX only")
	}
	// Don't put any shim on PATH. The system curl (if present) should NOT
	// match the shim dir, so the probe returns false.
	t.Setenv("PATH", "/usr/bin:/bin")
	ok, _, err := probeShimTier("/nonexistent/shims")
	if err != nil {
		// "command -v" failing because curl isn't installed is fine; it
		// surfaces as ok=false, err=nil. If it does error, we want to know.
		t.Logf("probe returned err (acceptable): %v", err)
	}
	if ok {
		t.Errorf("expected probe to NOT detect shim when only /usr/bin/curl is reachable")
	}
}

func TestWriteTierFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tier")
	if err := writeTierFile(path, "shim"); err != nil {
		t.Fatalf("writeTierFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "shim\n" {
		t.Errorf("tier file = %q, want %q", got, "shim\n")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-sbx-bootstrap/... -run "TestProbeShimTier|TestWriteTierFile" -v`
Expected: FAIL — `probeShimTier` and `writeTierFile` are undefined.

- [ ] **Step 3: Implement the probe and tier-file writer**

Create `cmd/agentsh-sbx-bootstrap/tier.go`:

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// probeShimTier runs `/bin/sh -c 'command -v curl'` and reports whether the
// resolved curl path lives under shimDir. Returns (ok, resolvedPath, err).
// A non-nil error means the probe couldn't be run at all (e.g. /bin/sh
// missing); a successful run with `ok=false` means curl is either absent or
// the system curl is winning over the shim.
func probeShimTier(shimDir string) (bool, string, error) {
	cmd := exec.Command("/bin/sh", "-c", "command -v curl")
	out, err := cmd.Output()
	if err != nil {
		// `command -v curl` exits 1 when curl isn't found; that's not an error
		// for our purposes — it just means the shim tier didn't apply.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, "", nil
		}
		return false, "", fmt.Errorf("probe: %w", err)
	}
	resolved := strings.TrimSpace(string(out))
	if resolved == "" {
		return false, "", nil
	}
	clean := filepath.Clean(shimDir)
	return strings.HasPrefix(resolved, clean+string(filepath.Separator)) || resolved == clean, resolved, nil
}

// writeTierFile writes the active tier name (e.g. "shim" or "none") followed
// by a trailing newline to path. Atomic via tmp+rename so concurrent readers
// (the SKILL.md tells the agent to `cat` this file) never see a half-written
// value. Creates parent dirs with mode 0755.
func writeTierFile(path, tier string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir tier dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(tier+"\n"), 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Wire into main**

Replace the trailing `// Tier probe lands in Task 5.` comment in `cmd/agentsh-sbx-bootstrap/main.go` with the probe step:

```go
	const defaultShimDir = "/usr/lib/agentsh/shims"
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
```

(Insert this block immediately after the `waitForSocket` call so the existing structure is preserved.)

- [ ] **Step 5: Run tests**

Run: `go test ./cmd/agentsh-sbx-bootstrap/... -v`
Expected: PASS.

- [ ] **Step 6: Run a quick end-to-end smoke locally**

Run:
```
mkdir -p /tmp/sbx-bootstrap-test/shims /tmp/sbx-bootstrap-test/run /tmp/sbx-bootstrap-test/etc
cat <<'EOF' >/tmp/sbx-bootstrap-test/shims/curl
#!/bin/sh
exit 0
EOF
chmod +x /tmp/sbx-bootstrap-test/shims/curl
PATH=/tmp/sbx-bootstrap-test/shims:$PATH AGENTSH_SHIM_DIR=/tmp/sbx-bootstrap-test/shims \
  go run ./cmd/agentsh-sbx-bootstrap \
    --template configs/policies/coding-agent.yaml \
    --overlay /dev/null \
    --policy /tmp/sbx-bootstrap-test/etc/default.yaml \
    --agentsh /bin/true \
    --server-config /dev/null \
    --socket /tmp/sbx-bootstrap-test/run/sock 2>&1 | tee /tmp/sbx-bootstrap-test/log
```
Expected: log line "shim tier active (curl -> /tmp/sbx-bootstrap-test/shims/curl)". The waitForSocket will time out but that's expected with `/bin/true` as the daemon; bootstrap continues regardless.

- [ ] **Step 7: Commit**

```bash
git add cmd/agentsh-sbx-bootstrap/tier.go cmd/agentsh-sbx-bootstrap/tier_test.go cmd/agentsh-sbx-bootstrap/main.go
git commit -m "bootstrap: shim-tier probe + /run/agentsh/tier writer"
```

---

## Task 6: Package the new artifacts via .goreleaser.yml

**Files:**
- Modify: `.goreleaser.yml`

Add the new bootstrap binary build, the shim symlinks under `/usr/lib/agentsh/shims/`, and the packaged policy template at `/usr/share/agentsh/coding-agent.template.yaml`. The existing `configs/policies/*.yaml` glob already installs the new `coding-agent.yaml` to `/etc/agentsh/policies/`, so that side is automatic.

- [ ] **Step 1: Add the bootstrap build target**

In `.goreleaser.yml`, after the `shim-darwin` build (around line 130, before the archives block — find the last `- id: shim-*` block), append a new linux-only build:

```yaml
  - id: sbx-bootstrap-linux
    main: ./cmd/agentsh-sbx-bootstrap
    binary: agentsh-sbx-bootstrap
    env:
      - CGO_ENABLED=0
    goos:
      - linux
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w -X main.version={{.Version}}
```

- [ ] **Step 2: Add the sbx-bootstrap build id to the linux .deb/.rpm nfpm `ids:` list**

In the `nfpms:` block (around line 300), the linux Debian/RPM package's `ids:` list already contains the agentsh and shim builds. Add `sbx-bootstrap-linux`:

```yaml
nfpms:
  - id: agentsh
    package_name: agentsh
    ids:
      - agentsh-linux-amd64
      - agentsh-linux-arm64
      - shim-linux
      - unixwrap-linux-amd64
      - unixwrap-linux-arm64
      - stub-linux
      - sbx-bootstrap-linux    # NEW: bootstrap binary lands in /usr/bin
```

- [ ] **Step 3: Add packaged template + shim symlink directory**

In the same `nfpms:` block's `contents:` section, after the existing `/usr/lib/agentsh/bash_startup.sh` entry, append:

```yaml
      # Coding-agent policy template for Docker Sandboxes mixin bootstrap.
      # Installed read-only — the bootstrap writes the merged result to
      # /etc/agentsh/policies/default.yaml on each sandbox start.
      - src: configs/policies/coding-agent.yaml
        dst: /usr/share/agentsh/coding-agent.template.yaml
        file_info:
          mode: 0644

      # Shim directory + symlinks (Docker Sandboxes mixin support).
      # /usr/lib/agentsh/shims is prepended to PATH inside sandboxes via
      # /etc/profile.d/agentsh.sh (written by the mixin kit's initFiles).
      - dst: /usr/lib/agentsh/shims
        type: dir
        file_info:
          mode: 0755
      - dst: /usr/lib/agentsh/shims/bash
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/sh
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/curl
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/wget
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/pip
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/pip3
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/npm
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/node
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/git
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/python
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/python3
        src: /usr/bin/agentsh-shell-shim
        type: symlink
      - dst: /usr/lib/agentsh/shims/rm
        src: /usr/bin/agentsh-shell-shim
        type: symlink

      # Packaged policy reference (also lives in repo at docs/policy-reference.md).
      - src: docs/policy-reference.md
        dst: /usr/share/doc/agentsh/policy-reference.md
        file_info:
          mode: 0644
```

(`docs/policy-reference.md` is created in Task 7. Leave the reference here so the packaging stays close to other doc entries.)

- [ ] **Step 4: Validate goreleaser config**

Run: `goreleaser check`
Expected: PASS, no warnings. (If goreleaser is not installed, install with `go install github.com/goreleaser/goreleaser/v2@latest`.)

- [ ] **Step 5: Build a snapshot to confirm artifacts produce**

Run: `goreleaser build --snapshot --clean --single-target --id sbx-bootstrap-linux`
Expected: success; binary at `dist/sbx-bootstrap-linux_linux_amd64_v1/agentsh-sbx-bootstrap`.

- [ ] **Step 6: Commit**

```bash
git add .goreleaser.yml
git commit -m "release: package sbx-bootstrap binary, shim symlinks, policy template"
```

---

## Task 7: Packaged policy reference doc

**Files:**
- Create: `docs/policy-reference.md`

The SKILL.md points the agent at `/usr/share/doc/agentsh/policy-reference.md` for the full grammar. This task lands a single user-facing reference that lives in the repo and is packaged into the OS bundle by Task 6's `nfpms.contents` entry.

This document is descriptive — no tests run against it directly. The validation gate is: SKILL.md (Task 9) references it and the smoke test (Task 9) confirms the file exists in the sandbox.

- [ ] **Step 1: Create the reference doc**

Create `docs/policy-reference.md`:

```markdown
# AgentSH policy reference (Docker Sandboxes edition)

This file ships at `/usr/share/doc/agentsh/policy-reference.md` inside any
Docker Sandbox that has the AgentSH mixin kit installed. It's the canonical
reference the agent's SKILL.md points at when you (or the agent) want to add
or change a rule.

For the full schema documented inline with examples, see
`/etc/agentsh/policies/default.yaml` — the merged policy the daemon is
currently enforcing.

## Inspecting the live state

| Question | Run |
|---|---|
| What enforcement tier is active? | `cat /run/agentsh/tier` (one of `shim`, `none`) |
| What policy is being enforced right now? | `cat /etc/agentsh/policies/default.yaml` |
| What are my overrides on top of the baked policy? | `cat /home/agent/.agentsh/policy.yaml` |
| Is the daemon running? | `pgrep -af 'agentsh server'` |

## Adding rules — `~/.agentsh/policy.yaml`

Write a partial policy. The bootstrap merges it on top of the baked
`coding-agent` template on next sandbox start. Rules that share a `name` with
a baked rule replace it; rules with new names append after the baked set.

```yaml
version: 1
name: my-overrides

file_rules:
  - name: allow-extra-write-area
    paths: ["/data/**"]
    operations: [write, create, mkdir, rename]
    decision: allow

  - name: allow-workspace-write     # overrides the baked rule by name
    paths: ["/workspace", "/workspace/**", "/scratch/**"]
    operations: [write, create, mkdir, chmod, rename]
    decision: allow

command_rules:
  - name: deny-aws-cli
    commands: [aws]
    decision: deny
    message: "aws-cli is not permitted in this sandbox"
```

## Rule kinds at a glance

- `file_rules` — file open/read/write/delete/stat/list, by glob path. Decisions: `allow`, `deny`, `approve`, `audit`, `soft_delete`, `redirect`.
- `command_rules` — process exec, by command name + optional argument regex. Decisions: `allow`, `deny`, `approve`, `audit`, `redirect`.
- `signal_rules` — signal sending. Decisions: `allow`, `deny`, `audit`, `approve`, `redirect`, `absorb`.
- `network_rules` — outbound connect by domain / port / CIDR. The Docker Sandbox proxy is the primary outbound-network gate inside a sandbox; AgentSH's network rules are layered on top and apply *before* the proxy.
- `unix_socket_rules` — AF_UNIX socket connect/bind/listen.

Each rule has `name`, `description`, the kind-specific selectors, `decision`, and an optional `message` (Go template; available variables: `.Path`, `.Command`, `.Args`, `.Decision`, `.Signal`, `.PID`).

## Where things live

| Path | Owner | Purpose |
|---|---|---|
| `/usr/share/agentsh/coding-agent.template.yaml` | OS package, read-only | Baked-in policy the bootstrap reads |
| `/home/agent/.agentsh/policy.yaml` | You | Override fragment (optional) |
| `/etc/agentsh/policies/default.yaml` | bootstrap (regenerated each start) | What the daemon enforces |
| `/etc/agentsh/config.yaml` | OS package | Daemon server config |
| `/run/agentsh/tier` | bootstrap | Active enforcement tier |
| `/run/agentsh/agentsh.sock` | daemon | Daemon control socket |
| `/var/log/agentsh/daemon.log` | daemon | Daemon stdout+stderr |
| `/var/log/agentsh/bootstrap.log` | bootstrap | Startup banner + tier probe result |

## Decision semantics quick reference

- `allow` — operation proceeds.
- `audit` — operation proceeds, emit an audit event.
- `deny` — operation refused; the agent gets EACCES (or equivalent).
- `approve` — operation blocks until a human approves out-of-band.
- `soft_delete` — for file delete/rmdir only: the path is moved to `/var/lib/agentsh/trash/` instead of being removed. Recoverable.
- `redirect` — for `command_rules` and `connect_redirects`: the operation is rewritten to a different command or destination.

## Reloading

In v1, the bootstrap re-runs only at sandbox start. To pick up a new
`~/.agentsh/policy.yaml`, restart the sandbox via Docker Sandboxes. v1.1 may
add an in-place reload.
```

- [ ] **Step 2: Commit**

```bash
git add docs/policy-reference.md
git commit -m "docs: policy-reference.md packaged with the kit for in-sandbox use"
```

---

## Task 8: install.sh installer script

**Files:**
- Create: `scripts/install-agentsh.sh`
- Test: `scripts/install-agentsh_test.sh`

The mixin kit's `install` command does `curl … install.sh | sh`. This task creates the script. It detects the package manager and installs the matching release artifact for the host's architecture.

The script is self-contained Bash. Validation is via `shellcheck` plus a tiny driver that invokes the script in a dry-run mode.

- [ ] **Step 1: Write a failing test**

Create `scripts/install-agentsh_test.sh`:

```bash
#!/usr/bin/env bash
# Smoke test for scripts/install-agentsh.sh.
# Runs the script with AGENTSH_DRY_RUN=1 and asserts it picks the right
# package manager + URL based on AGENTSH_FORCE_DETECT.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
script="$here/install-agentsh.sh"

# Test 1: detects dpkg
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=dpkg AGENTSH_ARCH=amd64 "$script" 2>&1 || true)
echo "$out" | grep -q "dpkg.*agentsh_.*_linux_amd64.deb" || {
  echo "FAIL: dpkg branch missing or wrong URL"
  echo "----- output -----"
  echo "$out"
  exit 1
}

# Test 2: detects rpm
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=rpm AGENTSH_ARCH=amd64 "$script" 2>&1 || true)
echo "$out" | grep -q "rpm.*agentsh-.*\.x86_64\.rpm" || {
  echo "FAIL: rpm branch missing or wrong URL"
  echo "----- output -----"
  echo "$out"
  exit 1
}

# Test 3: detects apk
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=apk AGENTSH_ARCH=amd64 "$script" 2>&1 || true)
echo "$out" | grep -q "apk.*agentsh_.*_linux_amd64.apk" || {
  echo "FAIL: apk branch missing or wrong URL"
  echo "----- output -----"
  echo "$out"
  exit 1
}

# Test 4: unknown package manager fails fast
if AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=none "$script" 2>/dev/null; then
  echo "FAIL: expected non-zero exit when no package manager detected"
  exit 1
fi

# Test 5: arm64 selects arm64 artifact
out=$(AGENTSH_DRY_RUN=1 AGENTSH_FORCE_DETECT=dpkg AGENTSH_ARCH=arm64 "$script" 2>&1 || true)
echo "$out" | grep -q "agentsh_.*_linux_arm64.deb" || {
  echo "FAIL: arm64 URL not generated"
  echo "----- output -----"
  echo "$out"
  exit 1
}

echo "OK install-agentsh.sh"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `chmod +x scripts/install-agentsh_test.sh && ./scripts/install-agentsh_test.sh`
Expected: FAIL — `scripts/install-agentsh.sh` does not exist.

- [ ] **Step 3: Create the installer**

Create `scripts/install-agentsh.sh`:

```bash
#!/bin/sh
# install-agentsh.sh — install AgentSH into a Linux container/VM.
#
# Used by the Docker Sandboxes mixin kit; also safe to run interactively
# on any supported Linux. Detects the host's package manager and
# downloads the matching `.deb`, `.rpm`, or `.apk` from the latest
# AgentSH GitHub release.
#
# Env knobs (all optional):
#   AGENTSH_VERSION    Pinned release tag (default: latest)
#   AGENTSH_ARCH       amd64 | arm64 (default: detected via uname -m)
#   AGENTSH_DRY_RUN    1 = print actions without downloading/installing
#   AGENTSH_FORCE_DETECT  dpkg | rpm | apk | none (test hook)
#
# Exit codes:
#   0 success
#   1 detection failure (no supported package manager)
#   2 download failure
#   3 install failure

set -eu

base_url() {
  if [ -n "${AGENTSH_VERSION:-}" ]; then
    printf '%s' "https://github.com/erans/agentsh/releases/download/${AGENTSH_VERSION}"
  else
    printf '%s' "https://github.com/erans/agentsh/releases/latest/download"
  fi
}

detect_arch() {
  if [ -n "${AGENTSH_ARCH:-}" ]; then
    printf '%s' "$AGENTSH_ARCH"
    return
  fi
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) printf 'unsupported' ;;
  esac
}

detect_pm() {
  if [ -n "${AGENTSH_FORCE_DETECT:-}" ]; then
    printf '%s' "$AGENTSH_FORCE_DETECT"
    return
  fi
  if command -v dpkg >/dev/null 2>&1; then printf 'dpkg'; return; fi
  if command -v rpm  >/dev/null 2>&1; then printf 'rpm';  return; fi
  if command -v apk  >/dev/null 2>&1; then printf 'apk';  return; fi
  printf 'none'
}

run() {
  if [ "${AGENTSH_DRY_RUN:-}" = "1" ]; then
    echo "DRY: $*"
  else
    "$@"
  fi
}

main() {
  arch=$(detect_arch)
  if [ "$arch" = "unsupported" ]; then
    echo "install-agentsh: unsupported architecture $(uname -m)" >&2
    exit 1
  fi

  pm=$(detect_pm)
  case "$pm" in
    dpkg)
      url="$(base_url)/agentsh_VERSION_linux_${arch}.deb"
      tmp="/tmp/agentsh.deb"
      echo "install-agentsh: using dpkg ($url)"
      run sh -c "curl -fsSL '$url' -o '$tmp'" || exit 2
      run dpkg -i "$tmp" || exit 3
      ;;
    rpm)
      rpmarch=$([ "$arch" = "amd64" ] && echo x86_64 || echo aarch64)
      url="$(base_url)/agentsh-VERSION.${rpmarch}.rpm"
      tmp="/tmp/agentsh.rpm"
      echo "install-agentsh: using rpm ($url)"
      run sh -c "curl -fsSL '$url' -o '$tmp'" || exit 2
      run rpm -Uvh --replacepkgs "$tmp" || exit 3
      ;;
    apk)
      url="$(base_url)/agentsh_VERSION_linux_${arch}.apk"
      tmp="/tmp/agentsh.apk"
      echo "install-agentsh: using apk ($url)"
      run sh -c "curl -fsSL '$url' -o '$tmp'" || exit 2
      run apk add --allow-untrusted "$tmp" || exit 3
      ;;
    none)
      echo "install-agentsh: no supported package manager (dpkg/rpm/apk) found" >&2
      exit 1
      ;;
    *)
      echo "install-agentsh: unknown package manager $pm" >&2
      exit 1
      ;;
  esac

  echo "install-agentsh: done"
}

main "$@"
```

- [ ] **Step 4: Run the test**

Run: `chmod +x scripts/install-agentsh.sh && ./scripts/install-agentsh_test.sh`
Expected: PASS, prints `OK install-agentsh.sh`.

- [ ] **Step 5: Run shellcheck on both scripts**

Run: `shellcheck scripts/install-agentsh.sh scripts/install-agentsh_test.sh`
Expected: no errors. (If shellcheck isn't installed: `sudo apt-get install -y shellcheck` or skip with a note.)

- [ ] **Step 6: Commit**

```bash
git add scripts/install-agentsh.sh scripts/install-agentsh_test.sh
git commit -m "scripts: install-agentsh.sh for the Docker Sandboxes mixin kit"
```

---

## Task 9: The mixin kit directory itself

**Files:**
- Create: `docker/sbx-kit/spec.yaml`
- Create: `docker/sbx-kit/README.md`
- Create: `docker/sbx-kit/files/workspace/.claude/skills/agentsh/SKILL.md`
- Create: `docker/sbx-kit/files/home/agent/.agentsh/policy.yaml`
- Create: `docker/sbx-kit/tests/coding-agent-smoke.sh`
- Test: `docker/sbx-kit/spec_test.go`

The kit tree gets a Go test that parses `spec.yaml` and checks the structural invariants we care about (manifest fields, shape of `commands.install` / `initFiles` / `startup`). The test lives under `docker/sbx-kit/` and runs as part of `go test ./...`.

- [ ] **Step 1: Write the failing kit-spec test**

Create `docker/sbx-kit/spec_test.go`:

```go
// Package sbxkit hosts a structural test for spec.yaml so a fresh engineer
// can't break the manifest format without CI catching it.
package sbxkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type kitSpec struct {
	SchemaVersion string   `yaml:"schemaVersion"`
	Kind          string   `yaml:"kind"`
	Name          string   `yaml:"name"`
	DisplayName   string   `yaml:"displayName"`
	Description   string   `yaml:"description"`
	Commands      kitCmds  `yaml:"commands"`
}

type kitCmds struct {
	Install   []kitInstall   `yaml:"install"`
	InitFiles []kitInitFile  `yaml:"initFiles"`
	Startup   []kitStartup   `yaml:"startup"`
}

type kitInstall struct {
	Command     string `yaml:"command"`
	User        string `yaml:"user"`
	Description string `yaml:"description"`
}

type kitInitFile struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
	Mode    string `yaml:"mode"`
}

type kitStartup struct {
	Command     []string `yaml:"command"`
	User        string   `yaml:"user"`
	Background  bool     `yaml:"background"`
	Description string   `yaml:"description"`
}

func loadSpec(t *testing.T) *kitSpec {
	t.Helper()
	path := filepath.Join("spec.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spec.yaml: %v", err)
	}
	var s kitSpec
	if err := yaml.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse spec.yaml: %v", err)
	}
	return &s
}

func TestSpecYAML_TopLevel(t *testing.T) {
	s := loadSpec(t)
	if s.SchemaVersion != "1" {
		t.Errorf("schemaVersion = %q, want %q", s.SchemaVersion, "1")
	}
	if s.Kind != "mixin" {
		t.Errorf("kind = %q, want %q", s.Kind, "mixin")
	}
	if s.Name != "agentsh" {
		t.Errorf("name = %q, want %q", s.Name, "agentsh")
	}
}

func TestSpecYAML_InstallReferencesInstallScript(t *testing.T) {
	s := loadSpec(t)
	if len(s.Commands.Install) != 1 {
		t.Fatalf("expected exactly one install command, got %d", len(s.Commands.Install))
	}
	cmd := s.Commands.Install[0].Command
	if !strings.Contains(cmd, "install.sh") {
		t.Errorf("install command does not curl install.sh: %q", cmd)
	}
	if s.Commands.Install[0].User != "0" {
		t.Errorf("install user = %q, want %q (root)", s.Commands.Install[0].User, "0")
	}
}

func TestSpecYAML_InitFilesSetShimPath(t *testing.T) {
	s := loadSpec(t)
	var foundProfile, foundEnv bool
	for _, f := range s.Commands.InitFiles {
		if f.Path == "/etc/profile.d/agentsh.sh" {
			foundProfile = true
			if !strings.Contains(f.Content, "/usr/lib/agentsh/shims") {
				t.Errorf("profile.d entry does not export shim PATH: %q", f.Content)
			}
		}
		if f.Path == "/etc/environment.d/10-agentsh.conf" {
			foundEnv = true
			if !strings.Contains(f.Content, "/usr/lib/agentsh/shims") {
				t.Errorf("environment.d entry does not include shim PATH: %q", f.Content)
			}
		}
	}
	if !foundProfile {
		t.Error("initFiles missing /etc/profile.d/agentsh.sh entry")
	}
	if !foundEnv {
		t.Error("initFiles missing /etc/environment.d/10-agentsh.conf entry")
	}
}

func TestSpecYAML_StartupInvokesBootstrap(t *testing.T) {
	s := loadSpec(t)
	if len(s.Commands.Startup) != 1 {
		t.Fatalf("expected exactly one startup command, got %d", len(s.Commands.Startup))
	}
	cmd := s.Commands.Startup[0]
	if len(cmd.Command) == 0 || cmd.Command[0] != "/usr/bin/agentsh-sbx-bootstrap" {
		t.Errorf("startup command = %v, want first element /usr/bin/agentsh-sbx-bootstrap", cmd.Command)
	}
	if !cmd.Background {
		t.Error("startup command must be background:true")
	}
}

func TestKitFiles_SkillExists(t *testing.T) {
	if _, err := os.Stat(filepath.Join("files", "workspace", ".claude", "skills", "agentsh", "SKILL.md")); err != nil {
		t.Errorf("SKILL.md missing: %v", err)
	}
}

func TestKitFiles_OverrideStubExists(t *testing.T) {
	if _, err := os.Stat(filepath.Join("files", "home", "agent", ".agentsh", "policy.yaml")); err != nil {
		t.Errorf("override stub missing: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./docker/sbx-kit/... -v`
Expected: FAIL — spec.yaml missing.

- [ ] **Step 3: Create the spec.yaml**

Create `docker/sbx-kit/spec.yaml`:

```yaml
# AgentSH mixin kit for Docker Sandboxes.
# See docs/superpowers/specs/2026-05-11-docker-sandboxes-mixin-kit-design.md
# Invoke: sbx run <agent> --kit git+https://github.com/erans/agentsh.git#dir=docker/sbx-kit

schemaVersion: "1"
kind: mixin
name: agentsh
displayName: AgentSH
description: Policy-enforced execution gateway for AI coding agents

commands:
  install:
    - command: "/bin/sh -c 'curl -fsSL https://github.com/erans/agentsh/releases/latest/download/install.sh | sh'"
      user: "0"
      description: Install agentsh from the latest GitHub release

  initFiles:
    - path: /etc/profile.d/agentsh.sh
      content: 'export PATH=/usr/lib/agentsh/shims:$PATH'
      mode: "0644"

    - path: /etc/environment.d/10-agentsh.conf
      content: 'PATH=/usr/lib/agentsh/shims:/usr/local/bin:/usr/bin:/bin'
      mode: "0644"

  startup:
    - command: ["/usr/bin/agentsh-sbx-bootstrap"]
      user: "0"
      background: true
      description: Merge policy, start agentsh server, probe enforcement tier
```

- [ ] **Step 4: Create the override stub**

Create `docker/sbx-kit/files/home/agent/.agentsh/policy.yaml`:

```yaml
# AgentSH user-override fragment.
#
# Anything you write here merges on top of the baked coding-agent policy at
# /usr/share/agentsh/coding-agent.template.yaml on the next sandbox start.
# Rules that share a `name` with a baked rule replace it; rules with new
# names append after the baked set.
#
# Reference: /usr/share/doc/agentsh/policy-reference.md
#
# Example (uncomment to use):
#
# version: 1
# name: my-overrides
# file_rules:
#   - name: allow-extra-write-area
#     paths: ["/data/**"]
#     operations: [write, create, mkdir, rename]
#     decision: allow
```

- [ ] **Step 5: Create the SKILL.md**

Create `docker/sbx-kit/files/workspace/.claude/skills/agentsh/SKILL.md`:

```markdown
---
name: agentsh
description: Use when the user asks about AgentSH policy, sandbox enforcement, audit events, or what file/network/command operations are allowed inside this Docker Sandbox. Read /run/agentsh/tier for the active enforcement mode, /etc/agentsh/policies/default.yaml for the merged active policy, and /home/agent/.agentsh/policy.yaml for the user-overlay fragment.
---

# AgentSH in this sandbox

This sandbox has AgentSH installed via the Docker Sandboxes mixin kit. It
enforces a policy on file, network, command, and signal operations performed
by you and your subprocesses.

## Inspect the live state

| Question | Run |
|---|---|
| What enforcement tier is active? | `cat /run/agentsh/tier` (one of `shim`, `none`) |
| What policy is being enforced right now? | `cat /etc/agentsh/policies/default.yaml` |
| What are my overrides on top of the baked policy? | `cat /home/agent/.agentsh/policy.yaml` |
| Is the daemon running? | `pgrep -af 'agentsh server'` |
| Full grammar reference | `cat /usr/share/doc/agentsh/policy-reference.md` |

## Extend the policy

Write a partial YAML policy to `/home/agent/.agentsh/policy.yaml`. The
bootstrap merges it on top of the baked `coding-agent` template on the next
sandbox start. Rules that share a `name` with a baked rule replace it;
rules with new names append.

Minimal example:

```yaml
version: 1
name: my-overrides
file_rules:
  - name: allow-data-area
    paths: ["/data/**"]
    operations: [write, create, mkdir, rename]
    decision: allow
```

Restart the sandbox via Docker Sandboxes to pick up the change. In-place
reload is not supported in v1.

## Common patterns

- Let the agent write outside `/workspace`: add a `file_rules` entry with `decision: allow` for the new paths.
- Block a command unconditionally: add a `command_rules` entry with `decision: deny`.
- Soft-delete instead of hard-delete on a path: `decision: soft_delete` in a `file_rules` entry for `delete`/`rmdir` operations.
- Audit (don't block) a pattern: `decision: audit`.

For the full grammar — every field, every decision value, available
templating variables — read `/usr/share/doc/agentsh/policy-reference.md`.

## When the tier is `none`

That means the bootstrap couldn't confirm the shim PATH made it past the
agent's entrypoint, OR the daemon failed to start. Check
`/var/log/agentsh/bootstrap.log` and `/var/log/agentsh/daemon.log` for the
reason. The agent will continue to run — AgentSH never blocks the agent's
startup — but enforcement is degraded to advisory.
```

- [ ] **Step 6: Create the smoke test script**

Create `docker/sbx-kit/tests/coding-agent-smoke.sh`:

```bash
#!/usr/bin/env bash
# Manual smoke test exercised inside a Docker Sandbox that has the AgentSH
# mixin kit installed. Run via:
#   sbx exec <session> bash /workspace/.claude/skills/agentsh/coding-agent-smoke.sh
#
# Or copy this file into the sandbox manually and run it as the agent user.
#
# Each check prints PASS / FAIL. Exits non-zero on any FAIL.

set -u

pass=0
fail=0

assert() {
  local label="$1"
  local got="$2"
  local want="$3"
  if [ "$got" = "$want" ]; then
    echo "PASS: $label"
    pass=$((pass+1))
  else
    echo "FAIL: $label (got=%q want=%q)"
    printf 'FAIL: %s (got=%q, want=%q)\n' "$label" "$got" "$want" >&2
    fail=$((fail+1))
  fi
}

assert_contains() {
  local label="$1"
  local got="$2"
  local want="$3"
  if printf '%s' "$got" | grep -q -- "$want"; then
    echo "PASS: $label"
    pass=$((pass+1))
  else
    echo "FAIL: $label (output did not contain $want)"
    echo "----- got: -----"
    printf '%s\n' "$got"
    echo "----------------"
    fail=$((fail+1))
  fi
}

# Check 1: tier file says shim
got=$(cat /run/agentsh/tier 2>/dev/null || echo missing)
assert "tier file = shim" "$got" "shim"

# Check 2: curl resolves under the shim dir
resolved=$(command -v curl)
assert_contains "curl resolves under shim dir" "$resolved" "/usr/lib/agentsh/shims"

# Check 3: cat ~/.ssh/id_rsa is denied (no such file is fine; we expect either ENOENT or EACCES via deny)
mkdir -p "$HOME/.ssh"
printf 'fake-key\n' > "$HOME/.ssh/id_rsa.smoke"
out=$(cat "$HOME/.ssh/id_rsa.smoke" 2>&1) && rc=0 || rc=$?
rm -f "$HOME/.ssh/id_rsa.smoke"
if [ "$rc" -ne 0 ]; then
  echo "PASS: cat ~/.ssh/id_rsa.smoke denied (rc=$rc)"
  pass=$((pass+1))
else
  echo "FAIL: cat ~/.ssh/id_rsa.smoke succeeded — deny rule did not fire"
  echo "----- got: -----"
  echo "$out"
  echo "----------------"
  fail=$((fail+1))
fi

# Check 4: sudo is denied
out=$(sudo whoami 2>&1) && rc=0 || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "PASS: sudo denied (rc=$rc)"
  pass=$((pass+1))
else
  echo "FAIL: sudo succeeded — deny rule did not fire"
  echo "----- got: -----"
  echo "$out"
  echo "----------------"
  fail=$((fail+1))
fi

# Check 5: soft-delete on /workspace
mkdir -p /workspace
echo "$$" > /workspace/smoke.tmp
rm /workspace/smoke.tmp 2>/dev/null || true
if [ -f /workspace/smoke.tmp ]; then
  echo "FAIL: /workspace/smoke.tmp still present after rm"
  fail=$((fail+1))
else
  # Look for it in the trash directory
  if find /var/lib/agentsh/trash -name smoke.tmp 2>/dev/null | grep -q smoke.tmp; then
    echo "PASS: soft-delete recoverable"
    pass=$((pass+1))
  else
    echo "FAIL: soft-delete trash entry not found"
    fail=$((fail+1))
  fi
fi

echo
echo "summary: $pass pass, $fail fail"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
```

- [ ] **Step 7: Create the kit README**

Create `docker/sbx-kit/README.md`:

```markdown
# AgentSH mixin kit for Docker Sandboxes

This is a [Docker Sandboxes mixin kit](https://docs.docker.com/ai/sandboxes/customize/kits/)
that installs [AgentSH](https://github.com/erans/agentsh) into any sandbox at
creation and routes the agent's command-level activity through a
coding-agent-tuned policy.

## Use

```
sbx run <agent> --kit git+https://github.com/erans/agentsh.git#dir=docker/sbx-kit
```

Works with `claude`, `opencode`, `gemini`, and any agent kit derived from
`docker/sandbox-templates:shell-docker`.

## Verify

```
sbx exec <session> cat /run/agentsh/tier              # expect: shim
sbx exec <session> cat /etc/agentsh/policies/default.yaml
sbx exec <session> pgrep -af 'agentsh server'
```

For a deeper smoke test, run `tests/coding-agent-smoke.sh` inside the
sandbox.

## OpenCode / Gemini setup

Claude Code auto-discovers `.claude/skills/agentsh/SKILL.md`. For other
agents, copy the SKILL into your agent's discovery path:

```
sbx exec <session> cp /workspace/.claude/skills/agentsh/SKILL.md /workspace/AGENTS.md
```

(Or symlink, or merge with your own `AGENTS.md` — whatever fits your flow.)

## Logs

| File | Purpose |
|---|---|
| `/var/log/agentsh/bootstrap.log` | Startup banner, policy-merge result, tier-probe result |
| `/var/log/agentsh/daemon.log`    | Daemon stdout+stderr |

## v1 enforcement tier

v1 ships shim-tier interception only: subprocess execs of common commands
are routed through AgentSH's shim binary. LD_PRELOAD and ptrace tiers are
planned (see the spec under
`docs/superpowers/specs/2026-05-11-docker-sandboxes-mixin-kit-design.md`).

## Override the policy

Write a partial YAML policy to `/home/agent/.agentsh/policy.yaml` inside the
sandbox. See `/usr/share/doc/agentsh/policy-reference.md` for the grammar.
Restart the sandbox to apply.
```

- [ ] **Step 8: Run the kit test**

Run: `go test ./docker/sbx-kit/... -v`
Expected: PASS.

- [ ] **Step 9: Run the full test suite to confirm nothing else broke**

Run: `go test ./... -count=1 -short`
Expected: PASS (or pre-existing flakes; new tests must pass).

- [ ] **Step 10: Commit**

```bash
git add docker/sbx-kit/
git commit -m "sbx: Docker Sandboxes mixin kit at docker/sbx-kit/"
```

---

## Task 10: Publish install.sh via the release workflow

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `.goreleaser.yml`

The mixin's `install` step curls `https://github.com/erans/agentsh/releases/latest/download/install.sh`. For that URL to resolve, the release pipeline must upload `scripts/install-agentsh.sh` as a release asset on every tag. GoReleaser's `release.extra_files` is the right hook.

- [ ] **Step 1: Add install.sh as a release extra file**

In `.goreleaser.yml`, find the `release:` top-level key (or add one if missing — it sits as a sibling of `nfpms:`, `archives:`, `checksum:`). Add or extend the `extra_files` list:

```yaml
release:
  extra_files:
    - glob: scripts/install-agentsh.sh
      name_template: install.sh
```

If the `release:` block doesn't exist yet, add the block at the end of `.goreleaser.yml` (before any closing). If it exists with other settings, just add the `extra_files` key.

- [ ] **Step 2: Validate goreleaser config**

Run: `goreleaser check`
Expected: PASS.

- [ ] **Step 3: Verify the workflow exercises the asset path**

Read `.github/workflows/release.yml`. Confirm it runs `goreleaser release` (it does — search for `goreleaser`). No further edits should be required; the `extra_files` setting plumbs into `goreleaser release` automatically.

- [ ] **Step 4: Local snapshot test**

Run:
```
goreleaser release --snapshot --clean --skip=publish
```
Look in `dist/` for `install.sh`. Expected: file present alongside `.deb`/`.rpm`/`.apk` artifacts.

- [ ] **Step 5: Commit**

```bash
git add .goreleaser.yml
git commit -m "release: publish install.sh as a release asset for the sbx mixin kit"
```

---

## Task 11: Final integration and end-to-end build verification

**Files:**
- (verification only — no source changes expected)

This task is the verification gate before merging. Run all the things that should now be green.

- [ ] **Step 1: Full Go test suite**

Run: `go test ./... -count=1`
Expected: PASS for everything new; pre-existing flakes (FlushLoop, TransportLoss) may show but should be documented as known.

- [ ] **Step 2: Cross-compile verification**

Run: `GOOS=windows go build ./...`
Expected: PASS. The bootstrap binary is Linux-only by goreleaser config; verify it doesn't break the Windows build by accident.

- [ ] **Step 3: Snapshot release**

Run: `goreleaser release --snapshot --clean --skip=publish`
Expected: `dist/` contains:
- `agentsh-sbx-bootstrap` binaries (linux amd64+arm64)
- `agentsh_<version>_linux_amd64.deb` (and arm64, rpm, archlinux variants)
- `install.sh`

- [ ] **Step 4: Inspect a .deb to confirm payload layout**

Run: `dpkg-deb -c dist/agentsh_*_linux_amd64.deb | grep -E '/(usr/lib/agentsh/shims|usr/share/agentsh|usr/bin/agentsh-sbx-bootstrap)'`
Expected: lists the new shim symlinks, `coding-agent.template.yaml`, and the bootstrap binary.

- [ ] **Step 5: Manual sandbox validation matrix**

Run the matrix from spec §11 against a live Docker Sandboxes install. Each agent gets `--kit git+https://github.com/erans/agentsh.git#dir=docker/sbx-kit&ref=<branch>`:

```
sbx run claude   --kit git+...#dir=docker/sbx-kit
sbx run opencode --kit git+...#dir=docker/sbx-kit
sbx run gemini   --kit git+...#dir=docker/sbx-kit
```

For each, run `tests/coding-agent-smoke.sh` and record results. Pass criteria:
- tier=shim
- curl resolves under `/usr/lib/agentsh/shims/`
- `cat ~/.ssh/id_rsa.smoke` denied
- `sudo whoami` denied
- soft-delete recoverable

If any agent kit fails the matrix, file a follow-up task and document the failure mode in the kit README's "Known limitations" section before tagging the release.

- [ ] **Step 6: Final commit (if any docs updated during validation)**

```bash
git add -A
git status
git commit -m "sbx: validation results from manual matrix" || echo "nothing to commit"
```

---

## Self-review

Coverage check against the spec:
- §1 Goal — Tasks 9, 10, 11 (kit tree + git URL invocation working end-to-end). ✅
- §2 Background — informational, not implemented. ✅
- §3 Non-goals — preserved as comments/scope in Tasks 5 and the kit README. ✅
- §4 Enforcement model (tier 1 shim) — Tasks 5, 9. Tiers 2/3 explicitly parked. ✅
- §5 Kit layout — Task 9. ✅
- §6 spec.yaml — Task 9. ✅
- §7 Install + startup flow — Tasks 3 (merge), 4 (daemon spawn + socket wait), 5 (tier probe + file). ✅
- §8 Default policy — Task 1. ✅
- §9 Self-teaching docs — Tasks 7 (policy-reference.md), 9 (SKILL.md + README). ✅
- §10 Prerequisites — Tasks 1 (#5 template), 2 (#4 merge helper), 3-5 (#3 bootstrap), 6 (#2 packaging), 7 (#6 docs), 8 (#1 install.sh), 10 (#1 release upload). ✅
- §11 Validation — Task 11 step 5 covers the manual matrix. ✅
- §12 Risk register — mitigations live in §7 of the spec and are inherent in the bootstrap design; no separate task. ✅
- §13 Out of scope — preserved across the tier-name string, the kit README, and the bootstrap probe stub. ✅

Placeholder scan: no `TBD`, `TODO`, or "fill in later" in the plan. ✅

Type consistency: `mergeAndWritePolicy(tmpl, overlay, out string)`, `MergeOverlay(base, overlay *Policy) *Policy`, `probeShimTier(shimDir string) (bool, string, error)`, `writeTierFile(path, tier string) error`, `spawnDaemon(bin string, args []string, logPath string) (*exec.Cmd, error)`, `waitForSocket(sockPath string, deadline time.Duration) error` — all consistent across Tasks 3-5. ✅

Plan covers the full spec; no gaps.
