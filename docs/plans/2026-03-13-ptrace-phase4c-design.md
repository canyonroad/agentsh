# Ptrace Phase 4c: Fargate E2E Test Infrastructure — Design

**Date:** 2026-03-13
**Author:** Eran / Canyon Road
**Status:** Design Complete

---

## Prerequisites

The following must be functional before Fargate E2E tests can pass (Phase E). Phases A-D can proceed without them.

1. **ptrace runtime wiring** — The server startup path must wire `TracerConfig` from `sandbox.ptrace` config into the ptrace `Tracer.Run()` loop. The tracer itself (`internal/ptrace/tracer.go`) is implemented and integration-tested, but the server entrypoint (`internal/server/server.go`) does not yet start the tracer. **Blocker for Phase E.** Merge criteria: `agentsh serve` with `sandbox.ptrace.enabled: true` starts the ptrace event loop.
2. **PID-file attach path** — `pid` mode with `target_pid_file` must poll for a PID file, read PID, and call `attachProcess()`. This attach-by-PID logic needs to be implemented in the tracer's `Run()` method. **Blocker for Phase E.** Merge criteria: integration test demonstrating attach via PID file.
3. **Policy handler interfaces** — `ExecHandler`, `FileHandler`, `NetworkHandler` must be wired from the server's policy engine to the tracer config. Currently exercised in `children` mode integration tests but not in server startup. **Blocker for Phase E.** Merge criteria: server passes policy handlers to `TracerConfig`.
4. **Tracer-ready sentinel** — After successful attach, the tracer must write a sentinel file (path from config, e.g., `/shared/tracer-ready`) so the workload knows tracing is active. **New work, implemented in Phase A** (see §8). Merge criteria: integration test verifying sentinel file creation after attach.

---

## Scope Decisions

### What's In

1. **Fargate E2E test infrastructure** — ECS task definition, CI plumbing, test harness that launches agentsh + workload as a multi-container Fargate task and verifies policy enforcement end-to-end.

2. **Seccomp availability probe** — A test that runs inside Fargate and reports whether `seccomp(SECCOMP_SET_MODE_FILTER)` with `SECCOMP_RET_TRACE` is available to containers. This determines whether prefilter injection is feasible on Fargate.

### What's Out (and Why)

#### Sidecar Auto-Discovery — Deferred (YAGNI)

**Decision:** Skip the `sidecar` attach mode. Use `pid` mode with a PID file instead.

**Why:** The current Fargate deployment has multiple sidecars. Auto-discovery requires heuristics to distinguish the workload process from all the sidecar processes (agentsh, Datadog, log routers, etc.). These heuristics are fragile — they break every time a sidecar is added or renamed. `pid` mode with a PID file is deterministic: the workload writes its PID, agentsh reads it. Works regardless of how many sidecars are in the task.

**Revisit when:** Someone has a deployment where modifying the workload entrypoint is not possible.

#### Seccomp Prefilter Injection — Deferred (Unverified Feasibility)

**Decision:** Do not implement prefilter injection for `pid` mode in this phase. Instead, add a probe to verify whether it's even possible on Fargate.

**Why:** Datadog CWS — the reference implementation for ptrace-on-Fargate — uses ptrace in "wrap mode" and explicitly states that "a seccomp profile cannot be applied" in this mode, accepting the ptracing overhead instead. This strongly suggests `seccomp(SECCOMP_SET_MODE_FILTER)` is either blocked or unreliable on Fargate. Building prefilter injection without verifying it works on the target platform would be wasted effort.

The Firecracker microVM applies its own seccomp filters to the VMM, and the container runtime applies a default Docker seccomp profile to the guest. Whether a process inside the guest can install additional BPF filters via `seccomp()` syscall is not documented by AWS.

**Revisit when:** The seccomp probe confirms availability on Fargate. If confirmed, prefilter injection becomes a straightforward follow-up using the Phase 4a syscall injection engine.

#### EKS Fargate Support — Deferred (No AWS SYS_PTRACE for EKS)

**Decision:** Do not implement EKS-specific support in this phase.

**Why:** As of March 2026, AWS has not shipped `SYS_PTRACE` capability support for EKS Fargate pods. The ptrace tracer requires this capability to attach to processes. ECS Fargate supports it via `pidMode: "task"` + `SYS_PTRACE` in the task definition. When AWS adds this to EKS, the main delta is Helm chart updates and the `pause` container skip logic (§20 in ptrace-support.md).

**Revisit when:** AWS announces `SYS_PTRACE` support for EKS Fargate.

---

## 1. Test Architecture

The Fargate E2E test harness:

1. **Build and push** agentsh + test workload images to ECR (done in CI before the test)
2. **Register** an ECS task definition with two containers (agentsh sidecar + workload) sharing a PID namespace via `pidMode: "task"`
3. **Run** the task on Fargate, wait for completion
4. **Pull** CloudWatch logs and assert policy enforcement via both agentsh audit events and workload exit codes
5. **Clean up** (stop task on timeout/failure, deregister task def)

### Assertion Strategy

Tests use **positive and negative controls** to distinguish policy enforcement from environmental failures:

- **Positive control (known-allowed):** Run a command that the test policy explicitly allows (e.g., `ls /tmp`). If this fails, the test environment is broken, not policy.
- **Negative control (known-denied):** Run a command that the test policy explicitly denies (e.g., `wget`). If this succeeds, enforcement is broken.
- **Agentsh audit events:** The test harness also checks agentsh container logs for structured audit events (`action=deny`, `command=wget`, etc.) to confirm the tracer made the decision, not a missing binary or filesystem permission.

This prevents false positives from `wget` not being installed, filesystem permission errors, or network unreachability being misinterpreted as policy enforcement.

CI integration: a new workflow job `fargate-e2e` gated on `vars.AWS_ECS_CLUSTER` — skipped when AWS isn't configured, runs when the variable is set. Credentials provided via `aws-actions/configure-aws-credentials` (OIDC preferred, static keys as fallback).

---

## 2. ECS Task Definition

- **Platform:** Fargate, Linux/X86_64
- **CPU/Memory:** 512 CPU / 1024 MiB (smallest comfortable pairing for two containers)
- **PID mode:** `task` (shared PID namespace — required for ptrace)
- **Networking:** `awsvpc` (required by Fargate), needs outbound internet for DNS tests

### Containers

**`agentsh` (sidecar):**
- Image: `${ECR_REGISTRY}/agentsh-test:${SHA}`
- `SYS_PTRACE` capability added
- Config: `attach_mode: "pid"`, `target_pid_file: "/shared/workload.pid"`, test policy baked in
- Health check: HTTP `/health` on API port
- On attach success: writes `/shared/tracer-ready` sentinel file
- Essential: true

**`workload`:**
- Image: `${ECR_REGISTRY}/agentsh-fargate-workload:${SHA}`
- Depends on agentsh container being `HEALTHY`
- Entrypoint: writes PID to `/shared/workload.pid`, polls for `/shared/tracer-ready` (up to 30s), then runs test script
- Essential: true

**Shared volume:**
- Name: `shared`
- Bind mount at `/shared` in both containers
- Used for PID file exchange and tracer-ready sentinel

**Logging:**
- CloudWatch Logs driver for both containers
- Log group: `/agentsh/fargate-e2e`
- Stream prefix: `test-${RUN_ID}`

### Container Ordering and Startup Synchronization

The workload container depends on agentsh being `HEALTHY` (ECS `dependsOn` with `HEALTHY` condition). After writing its PID, the workload polls for the `/shared/tracer-ready` sentinel file that agentsh writes after successfully attaching to the workload process:

```sh
# Wait for tracer to attach (condition-based, not time-based)
echo $$ > /shared/workload.pid
i=0
while [ ! -f /shared/tracer-ready ] && [ $i -lt 60 ]; do
  sleep 0.5
  i=$((i + 1))
done
if [ ! -f /shared/tracer-ready ]; then
  echo "SETUP:FAIL:tracer did not attach within 30s"
  exit 1
fi
```

This replaces a fixed `sleep 3` with condition-based readiness, eliminating race conditions under cold starts.

---

## 3. Test Workload Script

The workload runs a deterministic test script with positive and negative controls:

```sh
#!/bin/sh
echo $$ > /shared/workload.pid

# Wait for tracer to attach
i=0
while [ ! -f /shared/tracer-ready ] && [ $i -lt 60 ]; do
  sleep 0.5
  i=$((i + 1))
done
if [ ! -f /shared/tracer-ready ]; then
  echo "SETUP:FAIL:tracer did not attach within 30s"
  exit 1
fi
echo "SETUP:PASS:tracer attached"

echo "=== POSITIVE CONTROL ==="
# This command IS allowed by test policy — verifies environment works
ls /tmp > /dev/null 2>&1 && echo "CONTROL:PASS:allowed command ran" || echo "CONTROL:FAIL:allowed command blocked"

echo "=== EXEC TEST ==="
# wget is explicitly denied by test policy AND installed in the image
wget --spider http://example.com 2>&1 && echo "EXEC:FAIL:wget ran" || echo "EXEC:PASS:wget denied"

echo "=== FILE TEST ==="
# /etc/shadow.test is in a denied path pattern
touch /etc/shadow.test 2>&1 && echo "FILE:FAIL:write succeeded" || echo "FILE:PASS:write denied"

echo "=== NETWORK TEST ==="
# 169.254.169.254 (IMDS) is denied by network policy
# Use python3 (exec-allowed) to test network denial independently of exec denial
python3 -c "
import urllib.request, sys
try:
    urllib.request.urlopen('http://169.254.169.254/', timeout=2)
    print('NET:FAIL:connect succeeded')
except Exception:
    print('NET:PASS:connect denied')
" 2>&1

echo "=== SECCOMP PROBE ==="
/usr/local/bin/seccomp-probe && echo "SECCOMP:AVAILABLE" || echo "SECCOMP:UNAVAILABLE"

echo "=== DONE ==="
```

### Assertion Rules

The test harness scans **both** workload and agentsh CloudWatch logs:

1. **Workload logs:** `SETUP:PASS`, `CONTROL:PASS`, `EXEC:PASS`, `FILE:PASS`, `NET:PASS` must all be present. Any `FAIL` line fails the test. `SECCOMP` result is reported but informational.

2. **Agentsh logs:** Must contain audit events for each denied action (`action=deny` for wget, file write, IMDS connect). This confirms the tracer made the decision, not environmental happenstance.

3. **Positive control:** `CONTROL:PASS` must be present. If missing, the test environment is broken (not a policy issue) and the test is marked as an infrastructure failure, not a policy failure.

---

## 4. Seccomp Probe Binary

A small standalone Go program at `cmd/seccomp-probe/main.go`, installed at `/usr/local/bin/seccomp-probe` in the workload image:

```go
func main() {
    // 1. prctl(PR_SET_NO_NEW_PRIVS, 1)
    // 2. seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
    //    where prog is a trivial BPF program: RET_ALLOW for all syscalls
    // 3. If both succeed: exit 0, print "seccomp_filter: available"
    // 4. If either fails: exit 1, print error with errno
}
```

The BPF program allows everything (`RET_ALLOW`) — it doesn't actually filter anything. We just want to know if the `seccomp()` syscall is permitted by the Fargate environment. The binary is cross-compiled (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0`) and `COPY`'d into the workload Dockerfile.

---

## 5. Test Harness

Location: `internal/integration/fargate/fargate_test.go`
Build tag: `//go:build fargate`

Uses `aws-sdk-go-v2/service/ecs` and `aws-sdk-go-v2/service/cloudwatchlogs`.

### Flow

1. **Setup:** Load AWS config from environment. Create ECS + CloudWatch clients. Use pre-existing cluster (name from `AWS_ECS_CLUSTER` env var).

2. **Register task def:** Build the task definition struct in Go with both containers, shared volume, PID mode, SYS_PTRACE. Register via `RegisterTaskDefinition`.

3. **Run task:** `RunTask` with Fargate launch type, subnet and security group from env vars, auto-assign public IP for outbound internet.

4. **Wait:** Poll `DescribeTasks` with status-based progress logging until task reaches `STOPPED` (timeout: 300s). On each poll, log current task status (`PROVISIONING` → `PENDING` → `RUNNING` → `STOPPED`). On timeout, call `StopTask` with reason `"E2E test timeout"` before failing.

5. **Assert:** Retry CloudWatch `GetLogEvents` with up to 30s backoff to handle eventual consistency lag. Scan workload logs for `PASS`/`FAIL` markers. Scan agentsh logs for audit events. Report seccomp probe result separately.

6. **Cleanup (always runs, even on failure):**
   - Call `StopTask` if task is still running
   - Deregister task definition revision
   - Log group persists for post-mortem debugging
   - Log `stoppedReason` and per-container exit codes on failure for diagnostics

### Error Handling

- **Task fails to start:** Log `stoppedReason` from `DescribeTasks`, fail test with diagnostic message.
- **Container exits non-zero:** Log per-container `exitCode` and `reason` from task description.
- **CloudWatch logs missing:** Retry with exponential backoff (1s, 2s, 4s, ...) up to 30s. If still missing, fail with "logs not available" rather than false pass.
- **Partial log output:** If `DONE` marker is missing, report incomplete test run.

### Environment Variables (from CI secrets)

| Variable | Purpose |
|----------|---------|
| `AWS_REGION` | AWS region |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Credentials (or use OIDC) |
| `AGENTSH_TEST_IMAGE` | ECR URI for agentsh image |
| `WORKLOAD_TEST_IMAGE` | ECR URI for workload image |
| `AWS_ECS_CLUSTER` | ECS cluster name |
| `AWS_ECS_SUBNET` | Public subnet ID |
| `AWS_ECS_SECURITY_GROUP` | Security group (egress-only) |
| `AWS_ECS_EXECUTION_ROLE_ARN` | Task execution role (ECR pull + CW logs) |

---

## 6. CI Integration

New job in `.github/workflows/ci.yml`:

```yaml
fargate-e2e:
  if: >-
    github.event_name == 'push' &&
    github.ref == 'refs/heads/main' &&
    vars.AWS_ECS_CLUSTER != ''
  needs: [test-linux, integration]
  continue-on-error: true
  runs-on: ubuntu-latest
  timeout-minutes: 15
  steps:
    - checkout
    - setup Go
    - configure AWS credentials (from secrets)
    - login to ECR
    - build + push agentsh test image
    - build + push workload test image (with seccomp probe binary)
    - go test -v -tags=fargate -timeout 5m ./internal/integration/fargate/...
```

- **Only runs on main pushes** — not on PRs (costs money, needs secrets)
- **Gated on `vars.AWS_ECS_CLUSTER`** — skipped entirely when AWS isn't configured. This single gate covers all AWS resources (cluster implies credentials, subnet, etc. are also configured)
- **After unit + integration pass** — no point running Fargate if basic tests fail
- **15 min timeout** — generous for image push + Fargate cold start + test + teardown
- **Non-blocking on main:** If the job becomes flaky, it can be disabled by clearing the `AWS_ECS_CLUSTER` variable without code changes. The job is `continue-on-error: true` to avoid blocking main merges while Fargate infrastructure is being stabilized.

---

## 7. AWS Resources (Pre-Provisioned)

These must exist before the test runs. Documented in `docs/fargate-e2e-setup.md` (deliverable of this phase):

- **ECS cluster** (Fargate-only, no EC2 capacity providers)
- **ECR repositories** (two: `agentsh-test` + `agentsh-fargate-workload`, with lifecycle policy to keep last 5 images)
- **VPC** with public subnet + internet gateway
- **Security group** allowing all egress, no ingress
- **IAM task execution role** with `AmazonECSTaskExecutionRolePolicy` + CloudWatch Logs permissions
- **CloudWatch log group** `/agentsh/fargate-e2e` (7-day retention)
- **GitHub Actions:** `vars.AWS_ECS_CLUSTER` variable + credential secrets (OIDC preferred)

---

## 8. Implementation Phases

### Phase A: Scaffold, seccomp probe, and tracer-ready sentinel (no AWS needed)

1. Create `cmd/seccomp-probe/main.go` with the trivial BPF probe
2. Create `Dockerfile.fargate-test` for workload image (includes wget, python3, test script, seccomp-probe binary)
3. Create `internal/integration/fargate/` package scaffold with build tag
4. Add tracer-ready sentinel file support to `internal/ptrace/tracer.go` — after successful attach in `pid` mode, write a configurable sentinel file path (new `TracerConfig.ReadyFile` field). Include integration test.
5. Verify seccomp probe compiles and runs locally (`docker run --cap-add SYS_PTRACE`)

**Acceptance:** `seccomp-probe` binary runs in Docker, workload Dockerfile builds, sentinel file written after attach in integration test.

### Phase B: Task definition builder

5. Implement `task_definition.go` — Go function that builds the `RegisterTaskDefinitionInput` struct with both containers, shared volume, PID mode, capabilities, logging config
6. Unit test the task definition builder (verify struct fields, no AWS calls)

**Acceptance:** Task def builder produces correct JSON, unit tests pass.

### Phase C: Test harness (runner + waiter + log parser)

7. Implement `helpers.go` — AWS client setup, `runTask()`, `waitForTask()` with status logging and timeout, `stopTask()`, `fetchLogs()` with retry, `deregisterTaskDef()`
8. Implement `fargate_test.go` — `TestFargateE2E` orchestrating the full flow, assertion logic for positive/negative controls and audit events
9. Cleanup logic in `t.Cleanup()` — always stops task + deregisters task def
10. Unit tests for log parser — test `parseWorkloadLogs()` and `parseAuditEvents()` with mock log output (deterministic, no AWS calls). Covers: all-pass, exec-fail, missing-control, incomplete output (no DONE marker), mixed results.

**Acceptance:** Test compiles, log parser unit tests pass, harness logic is correct.

### Phase D: CI wiring

10. Add `fargate-e2e` job to `.github/workflows/ci.yml`
11. Write `docs/fargate-e2e-setup.md` with AWS resource provisioning instructions and GitHub Actions configuration

**Acceptance:** CI job appears in workflow, is skipped when `AWS_ECS_CLUSTER` is not set.

### Phase E: End-to-end validation (requires AWS credentials)

12. Provision AWS resources per setup guide
13. Configure GitHub Actions secrets/variables
14. Run the test, verify pass, check seccomp probe result

**Acceptance:** Test passes on real Fargate. Seccomp probe result documented.

---

## File Map

| Component | Location | Deliverable |
|-----------|----------|-------------|
| Seccomp probe binary | `cmd/seccomp-probe/main.go` | Phase A |
| Workload Dockerfile | `Dockerfile.fargate-test` | Phase A |
| Tracer-ready sentinel | `internal/ptrace/tracer.go` (ReadyFile support) | Phase A |
| ECS task def builder | `internal/integration/fargate/task_definition.go` | Phase B |
| Task def unit tests | `internal/integration/fargate/task_definition_test.go` | Phase B |
| Test helpers (AWS ops) | `internal/integration/fargate/helpers.go` | Phase C |
| Log parser + unit tests | `internal/integration/fargate/log_parser.go`, `log_parser_test.go` | Phase C |
| Test harness | `internal/integration/fargate/fargate_test.go` | Phase C |
| CI job | `.github/workflows/ci.yml` (`fargate-e2e` job) | Phase D |
| Setup guide | `docs/fargate-e2e-setup.md` | Phase D |

---

## References

- [Datadog eBPF-free agent guide](https://docs.datadoghq.com/security/workload_protection/guide/ebpf-free-agent/) — States seccomp profiles cannot be applied in ptrace wrap mode
- [AWS Fargate security considerations](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html) — Documents `CAP_SYS_PTRACE` availability
- [Firecracker security model](https://oboe.com/learn/mastering-aws-firecracker-microvms-1v69tav/security-model-and-resource-isolation-rcjern) — Jailer seccomp filter details
- `docs/ptrace-support.md` §7.3 — PID mode prefilter rationale
- `docs/ptrace-support.md` §8.1 — Sidecar discovery design (deferred)
- `docs/ptrace-support.md` §20 — EKS Fargate support design (deferred)
