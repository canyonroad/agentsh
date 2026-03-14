# Ptrace Phase 4c: Fargate E2E Test Infrastructure — Design

**Date:** 2026-03-13
**Author:** Eran / Canyon Road
**Status:** Design Complete

---

## Scope Decisions

### What's In

1. **Fargate E2E test infrastructure** — ECS task definition, CI plumbing, test harness that launches agentsh + workload as a multi-container Fargate task and verifies policy enforcement end-to-end. Ready to run once AWS credentials are provided.

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
4. **Pull** CloudWatch logs and assert policy enforcement worked (exec denied, file denied, network denied)
5. **Clean up** (deregister task def)

The test workload container runs a script that exercises each enforcement plane — tries to run blocked commands, open blocked files, connect to blocked addresses — and writes results to stdout. The agentsh sidecar uses `pid` mode with a PID file on a shared volume.

CI integration: a new workflow job `fargate-e2e` gated on `AWS_ACCESS_KEY_ID` secret presence — skipped when credentials aren't set, runs when they are.

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
- Essential: true

**`workload`:**
- Image: `${ECR_REGISTRY}/agentsh-fargate-workload:${SHA}`
- Depends on agentsh container being `HEALTHY`
- Entrypoint: writes PID to `/shared/workload.pid`, sleeps 3s for agentsh attach, runs test script
- Essential: true

**Shared volume:**
- Name: `shared`
- Bind mount at `/shared` in both containers
- Used for PID file exchange

**Logging:**
- CloudWatch Logs driver for both containers
- Log group: `/agentsh/fargate-e2e`
- Stream prefix: `test-${RUN_ID}`

### Container Ordering

The workload container depends on agentsh being `HEALTHY`. The workload writes its PID, then sleeps 3 seconds for agentsh to discover the PID file and attach. Then the test script runs. This is sufficient for E2E validation — production deployments can use tighter coordination.

---

## 3. Test Workload Script

The workload runs a deterministic test script that produces parseable output:

```sh
#!/bin/sh
echo $$ > /shared/workload.pid
sleep 3  # Wait for agentsh to attach

echo "=== EXEC TEST ==="
wget --version 2>&1 && echo "EXEC:FAIL:wget ran" || echo "EXEC:PASS:wget denied"

echo "=== FILE TEST ==="
touch /etc/shadow.test 2>&1 && echo "FILE:FAIL:write succeeded" || echo "FILE:PASS:write denied"

echo "=== NETWORK TEST ==="
curl -s --connect-timeout 2 http://169.254.169.254/ 2>&1 \
  && echo "NET:FAIL:connect succeeded" || echo "NET:PASS:connect denied"

echo "=== SECCOMP PROBE ==="
/shared/seccomp-probe && echo "SECCOMP:AVAILABLE" || echo "SECCOMP:UNAVAILABLE"

echo "=== DONE ==="
```

The test harness scans CloudWatch logs for `EXEC:PASS`, `FILE:PASS`, `NET:PASS` lines. Any `FAIL` line fails the test. The `SECCOMP` result is reported but does not fail the test — it's informational for the prefilter injection decision.

---

## 4. Seccomp Probe Binary

A small standalone Go program at `cmd/seccomp-probe/main.go`:

```go
func main() {
    // 1. prctl(PR_SET_NO_NEW_PRIVS, 1)
    // 2. seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
    //    where prog is a trivial BPF program: RET_ALLOW for all syscalls
    // 3. If both succeed: exit 0, print "seccomp_filter: available"
    // 4. If either fails: exit 1, print error with errno
}
```

The BPF program allows everything (`RET_ALLOW`) — it doesn't actually filter anything. We just want to know if the `seccomp()` syscall is permitted by the Fargate environment. The binary is cross-compiled into the workload image.

---

## 5. Test Harness

Location: `internal/integration/fargate/fargate_test.go`
Build tag: `//go:build fargate`

Uses `aws-sdk-go-v2/service/ecs` and `aws-sdk-go-v2/service/cloudwatchlogs`.

### Flow

1. **Setup:** Load AWS config from environment. Create ECS + CloudWatch clients. Use pre-existing cluster (name from `AWS_ECS_CLUSTER` env var).

2. **Register task def:** Build the task definition struct in Go with both containers, shared volume, PID mode, SYS_PTRACE. Register via `RegisterTaskDefinition`.

3. **Run task:** `RunTask` with Fargate launch type, subnet and security group from env vars, auto-assign public IP for outbound internet.

4. **Wait:** Poll `DescribeTasks` until task status is `STOPPED` (timeout: 120s).

5. **Assert:** Pull CloudWatch log events for the workload container's log stream. Scan for `PASS`/`FAIL` markers. Report seccomp probe result separately.

6. **Cleanup:** Deregister task definition revision. Log group persists for debugging.

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
- **Gated on `AWS_ECS_CLUSTER` variable** — skipped entirely when AWS isn't configured
- **After unit + integration pass** — no point running Fargate if basic tests fail
- **15 min timeout** — generous for task startup (~30s) + test (~30s) + teardown

---

## 7. AWS Resources (Pre-Provisioned)

These must exist before the test runs. Documented in `docs/fargate-e2e-setup.md`:

- **ECS cluster** (Fargate-only, no EC2 capacity providers)
- **ECR repository** (for agentsh + workload images, with lifecycle policy)
- **VPC** with public subnet + internet gateway
- **Security group** allowing all egress, no ingress
- **IAM task execution role** with `AmazonECSTaskExecutionRolePolicy` + CloudWatch Logs permissions
- **CloudWatch log group** `/agentsh/fargate-e2e`
- **GitHub Actions secrets** for credentials

---

## File Map

| Component | Location |
|-----------|----------|
| Seccomp probe binary | `cmd/seccomp-probe/main.go` |
| Workload Dockerfile | `Dockerfile.fargate-test` |
| ECS task def (Go code) | `internal/integration/fargate/task_definition.go` |
| Test harness | `internal/integration/fargate/fargate_test.go` |
| Test helpers | `internal/integration/fargate/helpers.go` |
| CI job | `.github/workflows/ci.yml` (`fargate-e2e` job) |
| Setup guide | `docs/fargate-e2e-setup.md` |

---

## References

- [Datadog eBPF-free agent guide](https://docs.datadoghq.com/security/workload_protection/guide/ebpf-free-agent/) — States seccomp profiles cannot be applied in ptrace wrap mode
- [AWS Fargate security considerations](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-security-considerations.html) — Documents `CAP_SYS_PTRACE` availability
- [Firecracker security model](https://oboe.com/learn/mastering-aws-firecracker-microvms-1v69tav/security-model-and-resource-isolation-rcjern) — Jailer seccomp filter details
- `docs/ptrace-support.md` §7.3 — PID mode prefilter rationale
- `docs/ptrace-support.md` §8.1 — Sidecar discovery design (deferred)
- `docs/ptrace-support.md` §20 — EKS Fargate support design (deferred)
