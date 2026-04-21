# Wrap AGENTSH_IN_SESSION Gating Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `agentsh wrap` inject `AGENTSH_IN_SESSION=1` only in strong interception modes, while preserving shim steering in fallback and no-`execve` modes.

**Architecture:** Add an explicit `SafeToBypassShellShim` capability bit to `types.WrapInitResponse`, compute it on the server from the actual wrap mode, and have the CLI use that bit exclusively when assembling child environments. Centralize wrap env construction in one helper so the direct-launch fallback and platform-specific wrap paths all share the same gating logic.

**Tech Stack:** Go, Cobra CLI, platform-specific wrap launchers, existing wrap API tests, existing integration testcontainers harness.

---

## File Structure

### Existing files to modify

- `pkg/types/sessions.go`
  - Add the server-to-CLI `SafeToBypassShellShim` field to `WrapInitResponse`.

- `internal/api/wrap.go`
  - Set `SafeToBypassShellShim=true` for ptrace wrap responses.
  - Set `SafeToBypassShellShim=execveEnabled` for Linux seccomp wrap responses.

- `internal/api/wrap_windows.go`
  - Set `SafeToBypassShellShim=true` for driver-based wrap responses.

- `internal/api/wrap_test.go`
  - Add regression tests for ptrace and Linux seccomp `execve` on/off cases.

- `internal/cli/wrap.go`
  - Add a shared helper that assembles the wrap child environment, including the conditional `AGENTSH_IN_SESSION` injection.
  - Route the direct-launch fallback through that helper with `bypassShellShim=false`.

- `internal/cli/wrap_linux.go`
  - Use the shared env helper for both ptrace and seccomp wrapper launch configs.

- `internal/cli/wrap_darwin.go`
  - Use the shared env helper and honor `wrapResp.SafeToBypassShellShim`.

- `internal/cli/wrap_windows.go`
  - Use the shared env helper and honor `wrapResp.SafeToBypassShellShim`.

- `internal/cli/wrap_test.go`
  - Add unit tests for the shared env helper.
  - Extend launch-config tests to assert marker presence/absence from the response bit.

- `internal/integration/agentsh_wrap_test.go`
  - Add a fallback integration regression test that proves the marker is absent.
  - Add a strong-interception integration regression test that proves the marker is present.

- `docs/cookbook/command-policies.md`
  - Clarify that nested shells bypass the shim only in strong wrap modes.

### Existing files to reuse without modification

- `internal/integration/seccomp_wrapper_test.go`
  - Reuse `buildSeccompBinaries` for the strong-mode integration test.

## Task 1: Add Server-Side Capability Signal

**Files:**
- Modify: `pkg/types/sessions.go`
- Modify: `internal/api/wrap.go`
- Modify: `internal/api/wrap_windows.go`
- Test: `internal/api/wrap_test.go`

- [ ] **Step 1: Write the failing wrap-init tests**

Add these tests to `internal/api/wrap_test.go` near the existing `wrapInitCore` response tests:

```go
func TestWrapInit_SafeToBypassShellShim_Ptrace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	app, mgr := newTestAppForWrap(t, cfg)
	app.ptraceTracer = struct{}{}

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}
	if !resp.SafeToBypassShellShim {
		t.Fatal("expected SafeToBypassShellShim=true in ptrace mode")
	}
}

func TestWrapInit_SafeToBypassShellShim_SeccompExecveEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = true
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}
	if !resp.SafeToBypassShellShim {
		t.Fatal("expected SafeToBypassShellShim=true when seccomp execve interception is enabled")
	}
}

func TestWrapInit_SafeToBypassShellShim_SeccompExecveDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.Execve.Enabled = false
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("wrapInitCore: %v", err)
	}
	if resp.SafeToBypassShellShim {
		t.Fatal("expected SafeToBypassShellShim=false when seccomp execve interception is disabled")
	}
}
```

- [ ] **Step 2: Run the new API tests and verify they fail**

Run:

```bash
go test ./internal/api -run 'TestWrapInit_SafeToBypassShellShim_'
```

Expected:

```text
FAIL
... resp.SafeToBypassShellShim undefined ...
```

- [ ] **Step 3: Add the response field and set it in wrap-init responses**

Update `pkg/types/sessions.go`:

```go
type WrapInitResponse struct {
	PtraceMode            bool              `json:"ptrace_mode,omitempty"`
	SafeToBypassShellShim bool              `json:"safe_to_bypass_shell_shim,omitempty"`
	WrapperBinary         string            `json:"wrapper_binary"`
	StubBinary            string            `json:"stub_binary,omitempty"`
	SeccompConfig         string            `json:"seccomp_config"`
	NotifySocket          string            `json:"notify_socket"`
	SignalSocket          string            `json:"signal_socket,omitempty"`
	WrapperEnv            map[string]string `json:"wrapper_env"`
}
```

Update the Linux ptrace return in `internal/api/wrap.go`:

```go
return types.WrapInitResponse{
	PtraceMode:            true,
	SafeToBypassShellShim: true,
	NotifySocket:          notifySocketPath,
}, http.StatusOK, nil
```

Update the Linux seccomp return in `internal/api/wrap.go`:

```go
return types.WrapInitResponse{
	WrapperBinary:         wrapperPath,
	StubBinary:            stubPath,
	SeccompConfig:         string(cfgJSON),
	NotifySocket:          notifySocketPath,
	SignalSocket:          signalSocketPath,
	WrapperEnv:            wrapperEnv,
	SafeToBypassShellShim: execveEnabled,
}, http.StatusOK, nil
```

Update the Windows return in `internal/api/wrap_windows.go`:

```go
return types.WrapInitResponse{
	StubBinary:            stubPath,
	SafeToBypassShellShim: true,
}, http.StatusOK, nil
```

- [ ] **Step 4: Run the targeted API tests and verify they pass**

Run:

```bash
go test ./internal/api -run 'TestWrapInit_SafeToBypassShellShim_|TestWrapInit_SeccompConfigContent'
```

Expected:

```text
ok  	github.com/agentsh/agentsh/internal/api
```

- [ ] **Step 5: Commit the server-side capability signal**

```bash
git add pkg/types/sessions.go internal/api/wrap.go internal/api/wrap_windows.go internal/api/wrap_test.go
git commit -m "feat(wrap): expose shell-shim bypass capability in wrap-init"
```

## Task 2: Gate CLI Environment Injection And Add Integration Coverage

**Files:**
- Modify: `internal/cli/wrap.go`
- Modify: `internal/cli/wrap_linux.go`
- Modify: `internal/cli/wrap_darwin.go`
- Modify: `internal/cli/wrap_windows.go`
- Test: `internal/cli/wrap_test.go`
- Test: `internal/integration/agentsh_wrap_test.go`

- [ ] **Step 1: Write the failing CLI unit tests**

Add these tests to `internal/cli/wrap_test.go`:

```go
func TestBuildWrapEnv_IncludesInSessionWhenBypassEnabled(t *testing.T) {
	env := buildWrapEnv([]string{"PATH=/usr/bin"}, "sess-123", "http://127.0.0.1:18080", true)
	envMap := make(map[string]bool)
	for _, e := range env {
		envMap[e] = true
	}

	assert.True(t, envMap["AGENTSH_SESSION_ID=sess-123"])
	assert.True(t, envMap["AGENTSH_SERVER=http://127.0.0.1:18080"])
	assert.True(t, envMap["AGENTSH_IN_SESSION=1"])
}

func TestBuildWrapEnv_OmitsInSessionWhenBypassDisabled(t *testing.T) {
	env := buildWrapEnv([]string{"PATH=/usr/bin"}, "sess-123", "http://127.0.0.1:18080", false)
	for _, e := range env {
		if e == "AGENTSH_IN_SESSION=1" {
			t.Fatal("did not expect AGENTSH_IN_SESSION when bypass is disabled")
		}
	}
}

func TestWrapLaunchConfig_EnvIncludesInSessionWhenSafe(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("wrap interception requires Linux or macOS")
	}

	mc := &mockWrapClient{
		wrapInitResp: types.WrapInitResponse{
			WrapperBinary:         "/bin/true",
			NotifySocket:          "/tmp/agentsh-notify-test.sock",
			SafeToBypassShellShim: true,
			WrapperEnv: map[string]string{
				"AGENTSH_SECCOMP_CONFIG": `{"unix_socket_enabled":true}`,
			},
		},
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}
	lcfg, err := setupWrapInterception(context.Background(), mc, "test-session", "/bin/echo", nil, cfg)
	require.NoError(t, err)

	envMap := make(map[string]bool)
	for _, e := range lcfg.env {
		envMap[e] = true
	}
	assert.True(t, envMap["AGENTSH_IN_SESSION=1"])
}

func TestWrapLaunchConfig_EnvOmitsInSessionWhenUnsafe(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("wrap interception requires Linux or macOS")
	}

	mc := &mockWrapClient{
		wrapInitResp: types.WrapInitResponse{
			WrapperBinary:         "/bin/true",
			NotifySocket:          "/tmp/agentsh-notify-test.sock",
			SafeToBypassShellShim: false,
			WrapperEnv: map[string]string{
				"AGENTSH_SECCOMP_CONFIG": `{"unix_socket_enabled":true}`,
			},
		},
	}

	cfg := &clientConfig{serverAddr: "http://127.0.0.1:18080"}
	lcfg, err := setupWrapInterception(context.Background(), mc, "test-session", "/bin/echo", nil, cfg)
	require.NoError(t, err)

	for _, e := range lcfg.env {
		if e == "AGENTSH_IN_SESSION=1" {
			t.Fatal("did not expect AGENTSH_IN_SESSION when wrap response marks bypass unsafe")
		}
	}
}
```

- [ ] **Step 2: Run the CLI unit tests and verify they fail**

Run:

```bash
go test ./internal/cli -run 'TestBuildWrapEnv_|TestWrapLaunchConfig_Env'
```

Expected:

```text
FAIL
... undefined: buildWrapEnv
... unknown field SafeToBypassShellShim in struct literal ...
```

- [ ] **Step 3: Write the failing integration regressions**

Extend `internal/integration/agentsh_wrap_test.go` with a strong-mode config and two regression tests:

```go
const wrapStrongTestConfigYAML = `
server:
  http:
    addr: "127.0.0.1:18080"
auth:
  type: "none"
logging:
  level: "info"
  format: "text"
  output: "stdout"
audit:
  enabled: false
  storage:
    sqlite_path: "/tmp/events.db"
sessions:
  base_dir: "/sessions"
sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
  unix_sockets:
    enabled: true
    wrapper_bin: "/usr/local/bin/agentsh-unixwrap"
  seccomp:
    unix_socket:
      enabled: true
    execve:
      enabled: true
policies:
  dir: "/policies"
  default: "agent-default"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
`

func TestWrapFallback_OmitsInSessionMarker(t *testing.T) {
	ctx := context.Background()
	bin := buildAgentshBinary(t)
	temp := t.TempDir()

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, wrapTestConfigYAML)

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "agent-default.yaml"), wrapTestPolicyYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	req := testcontainers.ContainerRequest{
		Image: "debian:bookworm-slim",
		Cmd: []string{
			"/usr/local/bin/agentsh", "wrap", "--",
			"/bin/sh", "-c", `if [ -n "$AGENTSH_IN_SESSION" ]; then echo MARKER_SET; else echo MARKER_UNSET; fi`,
		},
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(bin, "/usr/local/bin/agentsh"),
			testcontainers.BindMount(configPath, "/config.yaml"),
			testcontainers.BindMount(policiesDir, "/policies"),
			testcontainers.BindMount(workspace, "/workspace"),
		},
		Env: map[string]string{"AGENTSH_CONFIG": "/config.yaml"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForExit().WithExitTimeout(30 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	defer func() { _ = ctr.Terminate(context.Background()) }()

	logs, err := ctr.Logs(ctx)
	if err != nil {
		t.Fatalf("get logs: %v", err)
	}
	defer logs.Close()
	logBytes, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	if !strings.Contains(string(logBytes), "MARKER_UNSET") {
		t.Fatalf("expected MARKER_UNSET in fallback wrap output, got:\n%s", string(logBytes))
	}
}

func TestWrapStrongMode_SetsInSessionMarker(t *testing.T) {
	ctx := context.Background()
	agentshBin, unixwrapBin := buildSeccompBinaries(t)
	temp := t.TempDir()

	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, wrapStrongTestConfigYAML)

	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "agent-default.yaml"), wrapTestPolicyYAML)

	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	req := testcontainers.ContainerRequest{
		Image: "debian:bookworm-slim",
		Cmd: []string{
			"/usr/local/bin/agentsh", "wrap", "--",
			"/bin/sh", "-c", `if [ -n "$AGENTSH_IN_SESSION" ]; then echo MARKER_SET; else echo MARKER_UNSET; fi`,
		},
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(agentshBin, "/usr/local/bin/agentsh"),
			testcontainers.BindMount(unixwrapBin, "/usr/local/bin/agentsh-unixwrap"),
			testcontainers.BindMount(configPath, "/config.yaml"),
			testcontainers.BindMount(policiesDir, "/policies"),
			testcontainers.BindMount(workspace, "/workspace"),
		},
		Env: map[string]string{"AGENTSH_CONFIG": "/config.yaml"},
		Privileged: true,
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
		},
		WaitingFor: wait.ForExit().WithExitTimeout(60 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	defer func() { _ = ctr.Terminate(context.Background()) }()

	logs, err := ctr.Logs(ctx)
	if err != nil {
		t.Fatalf("get logs: %v", err)
	}
	defer logs.Close()
	logBytes, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read logs: %v", err)
	}
	if !strings.Contains(string(logBytes), "MARKER_SET") {
		t.Fatalf("expected MARKER_SET in strong wrap output, got:\n%s", string(logBytes))
	}
}
```

- [ ] **Step 4: Run the new CLI and integration tests and verify they fail for the right reason**

Run:

```bash
go test ./internal/cli -run 'TestBuildWrapEnv_|TestWrapLaunchConfig_Env'
go test -tags integration ./internal/integration -run 'TestWrapFallback_OmitsInSessionMarker|TestWrapStrongMode_SetsInSessionMarker'
```

Expected:

```text
ok    github.com/agentsh/agentsh/internal/cli ...    # after Task 1, compile still fails here until helper is added
--- FAIL: TestWrapStrongMode_SetsInSessionMarker
... expected MARKER_SET ...
```

The fallback integration test should already be green; the strong-mode test should fail until the CLI starts honoring `SafeToBypassShellShim`.

- [ ] **Step 5: Implement the shared env helper and wire it into all wrap launch paths**

Add this helper to `internal/cli/wrap.go` below `setupWrapInterception`:

```go
func buildWrapEnv(base []string, sessionID string, serverAddr string, bypassShellShim bool) []string {
	env := append([]string{}, base...)
	env = append(env,
		fmt.Sprintf("AGENTSH_SESSION_ID=%s", sessionID),
		fmt.Sprintf("AGENTSH_SERVER=%s", serverAddr),
	)
	if bypassShellShim {
		env = append(env, "AGENTSH_IN_SESSION=1")
	}
	return env
}
```

Update the direct fallback in `internal/cli/wrap.go`:

```go
agentProc.Env = buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, false)
```

Update the ptrace env in `internal/cli/wrap_linux.go`:

```go
env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
```

Update the Linux seccomp wrapper env in `internal/cli/wrap_linux.go`:

```go
env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
env = append(env, "AGENTSH_NOTIFY_SOCK_FD=3")
```

Update the macOS launch envs in `internal/cli/wrap_darwin.go`:

```go
env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
```

Update the Windows launch envs in `internal/cli/wrap_windows.go`:

```go
env := buildWrapEnv(os.Environ(), sessID, cfg.serverAddr, wrapResp.SafeToBypassShellShim)
```

- [ ] **Step 6: Run the CLI unit tests and integration tests and verify they pass**

Run:

```bash
go test ./internal/cli -run 'TestBuildWrapEnv_|TestWrapLaunchConfig_Env'
go test -tags integration ./internal/integration -run 'TestWrapFallback_OmitsInSessionMarker|TestWrapStrongMode_SetsInSessionMarker'
```

Expected:

```text
ok  	github.com/agentsh/agentsh/internal/cli
ok  	github.com/agentsh/agentsh/internal/integration
```

- [ ] **Step 7: Commit the CLI gating and integration coverage**

```bash
git add internal/cli/wrap.go internal/cli/wrap_linux.go internal/cli/wrap_darwin.go internal/cli/wrap_windows.go internal/cli/wrap_test.go internal/integration/agentsh_wrap_test.go
git commit -m "fix(wrap): gate AGENTSH_IN_SESSION on interception strength"
```

## Task 3: Update Docs And Run Final Verification

**Files:**
- Modify: `docs/cookbook/command-policies.md`

- [ ] **Step 1: Update the wrap docs to describe conditional shim bypass**

Edit the wrap section in `docs/cookbook/command-policies.md` to add a short note after the enforcement flow:

```md
Nested shell behavior depends on the active wrap mode:

- In strong interception modes (for example, ptrace or execve-intercepting wrap),
  nested `sh`/`bash` processes bypass the shell shim because descendant exec policy
  is already enforced by the wrap mechanism.
- In fallback or no-`execve` modes, nested shells still rely on the shim for
  command steering, so `AGENTSH_IN_SESSION` is intentionally not injected.
```

- [ ] **Step 2: Run the focused regression suite**

Run:

```bash
go test ./internal/api -run 'TestWrapInit_SafeToBypassShellShim_|TestWrapInit_SeccompConfigContent'
go test ./internal/cli -run 'TestBuildWrapEnv_|TestWrapLaunchConfig_Env|TestSetupWrapInterception_CallsWrapInit'
go test -tags integration ./internal/integration -run 'TestWrapAutoStart|TestWrapFallback_OmitsInSessionMarker|TestWrapStrongMode_SetsInSessionMarker'
```

Expected:

```text
ok  	github.com/agentsh/agentsh/internal/api
ok  	github.com/agentsh/agentsh/internal/cli
ok  	github.com/agentsh/agentsh/internal/integration
```

- [ ] **Step 3: Verify Windows compilation still works**

Run:

```bash
GOOS=windows go build ./...
```

Expected:

```text
# no output, exit 0
```

- [ ] **Step 4: Commit the docs and verification pass**

```bash
git add docs/cookbook/command-policies.md
git commit -m "docs(wrap): explain conditional shell-shim bypass"
```
