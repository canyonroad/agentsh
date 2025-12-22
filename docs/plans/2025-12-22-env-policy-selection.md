# Env-Policy Selection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow the server to pick the active policy by env var `AGENTSH_POLICY_NAME`, enforce an allowlist with safe fallback to the configured default, load the chosen policy on-demand once, and harden against downgrade attempts.

**Architecture:** Add a `policy.Manager` that binds the selected name at startup (env + allowlist), loads the corresponding YAML exactly once with strict parsing/validation, and returns a cached policy. The server constructs this manager from config and injects it wherever policy is needed.

**Tech Stack:** Go 1.21+, YAML v3, `sync.Once`, existing `internal/policy` + `internal/server` packages, Go testing.

---

### Task 0: Baseline with workspace-local Go cache

**Files:** none  
**Step 1:** Export workspace-local Go cache to avoid sandbox permission issues.  
`export GOCACHE=$(pwd)/.gocache`  
**Step 2:** Run baseline tests.  
`GOCACHE=$(pwd)/.gocache go test ./...`  
Expected: current failure (permission denied) disappears; note any real test failures.

---

### Task 1: Extend policy config for allowlist + manifest hook

**Files:**  
- Modify: `internal/config/config.go` (add `Allowed []string`, optional `ManifestPath string` to `PoliciesConfig`).  
- Modify: `config.yml` (document `allowed` list, `manifest_path`, env var name).  
- Modify: `docs/spec.md` (briefly note env-var selection and allowlist).  
**Step 1:** Add fields to `PoliciesConfig` struct (names: `Allowed`, `ManifestPath`).  
**Step 2:** Update sample config YAML keys with comments explaining usage.  
**Step 3:** Adjust any config validation (if present) to tolerate new keys.  
**Step 4:** Run targeted check (no tests yet rely on these fields).  
`GOCACHE=$(pwd)/.gocache go test ./internal/config/...`

---

### Task 2: Implement policy selection & single-flight loader

**Files:**  
- Create: `internal/policy/manager.go`  
- Create: `internal/policy/manager_test.go`  
- Modify: `internal/policy/load.go` (add strict decoder helper if needed).  
**Step 1:** Define `Manager` struct with fields: selectedName, dir, manifestPath, once, policy, err.  
**Step 2:** Add `selectPolicyName(envValue string, allowed []string, defaultName string) string` (validates `^[A-Za-z0-9_-]+$`, allowed check, fallback to default with reason).  
**Step 3:** In `Manager.Get(ctx)` use `sync.Once` to load `selectedName` via `ResolvePolicyPath`, `os.ReadFile`, `yaml.Decoder{KnownFields:true}`, optional manifest hash check, and semantic validation method on `Policy` (add minimal `Validate()` covering required fields/version>0). Cache result.  
**Step 4:** Add unit tests covering: allowed env value; disallowed env value falls back; invalid name rejected; missing file errors; hash mismatch errors (manifest stub); concurrency (parallel calls hit once).  
**Step 5:** Run package tests.  
`GOCACHE=$(pwd)/.gocache go test ./internal/policy/...`

---

### Task 3: Wire manager into server startup

**Files:**  
- Modify: `internal/server/server.go` (replace `resolvePolicyPath` usage with manager).  
- Modify: `internal/server/server_test.go` (update helpers to pass allowed list / env where needed).  
- Modify: any integration tests that construct config with policies (e.g., `internal/server/grpc*_test.go`, `internal/server/pty*_test.go`).  
**Step 1:** Build `policy.Manager` in server setup using cfg.Policies (dir, default, allowed, manifest) and env `AGENTSH_POLICY_NAME`.  
**Step 2:** Replace direct `ResolvePolicyPath` call with manager `Get` and `policy.NewEngine`. Keep fallback behavior identical for missing dir/default.  
**Step 3:** Adjust tests that expect default behavior to set `Policies.Allowed` to include `default` or leave empty to allow default fallback; add a new test proving env var selection + fallback.  
**Step 4:** Run server tests touched.  
`GOCACHE=$(pwd)/.gocache go test ./internal/server/...`

---

### Task 4: CLI and integration surface sanity

**Files:**  
- Modify: `internal/cli/policy_cmd.go` or helpers if they assume unrestricted names.  
- Modify: any creation flows that pass policy names (e.g., session creation) if allowlist needs enforcement client-side.  
- Tests: update/extend `internal/cli/policy_config_test.go` or session-related tests to reflect allowlist/env selection.  
**Step 1:** Ensure CLI uses the manager’s resolution rules when converting name->path (or at least respects allowlist in config when available).  
**Step 2:** Add/adjust tests to cover allowlist enforcement at CLI entry if applicable.  
**Step 3:** Run CLI tests.  
`GOCACHE=$(pwd)/.gocache go test ./internal/cli/...`

---

### Task 5: Documentation & examples

**Files:**  
- Modify: `README.md` (short note about `AGENTSH_POLICY_NAME` and allowed list).  
- Modify: `docs/spec.md` (policy section: env var, allowlist, manifest).  
- Add: brief changelog entry if repo has one (skip if none).  
**Step 1:** Document the selection order: env var (allowed) → default; unknown env values fall back with warning.  
**Step 2:** Mention optional manifest hash check and recommendation to mount policy dir read-only.  
**Step 3:** Ensure Dockerfile/example or compose references mention setting `AGENTSH_POLICY_NAME` as needed.  
**Step 4:** Proofread for clarity. No code changes.  

---

### Task 6: Full test sweep and cleanup

**Files:** none  
**Step 1:** Run full test suite with workspace-local cache.  
`GOCACHE=$(pwd)/.gocache go test ./...`  
**Step 2:** Address any regressions from allowlist/env logic.  
**Step 3:** Summarize results and prepare for PR (no commit yet unless requested).  
**Step 4:** If requested, push branch or open PR; otherwise leave branch ready.  

---

Execution options after review:
1) Subagent-driven in this session (use superpowers:subagent-driven-development).  
2) Parallel session using superpowers:executing-plans.  
