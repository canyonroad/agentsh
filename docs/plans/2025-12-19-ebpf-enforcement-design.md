# eBPF Connect Enforcement Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add optional eBPF-based enforcement for outbound TCP connects using a per-session allowlist populated by the existing policy engine; deny in BPF on connect if not allowed, with graceful fallback to user-space policy.

**Architecture:** User-space resolves allowed endpoints (family/ip/port) per session/command, populates a per-session BPF map, and sets `default_deny`. The cgroup connect hook looks up the tuple; if missing and default_deny=1, returns -EPERM and emits an event. DNS resolution is best-effort; a config flag controls strictness when DNS fails. User-space still logs events and retains proxy fallback.

**Tech Stack:** Go, cilium/ebpf, CO-RE BPF, cgroup hooks, existing policy engine; Linux-only enforcement, optional rDNS enrichment.

### Task 1: Config toggles and policy resolution knobs

**Files:** `internal/config/config.go`, `config.yml`, `internal/config/config_test.go`

Steps:
1) Add `sandbox.network.ebpf.enforce` (bool, default false) and `sandbox.network.ebpf.enforce_without_dns` (bool, default false).
2) Wire defaults and sample config; tests for defaults and required=>enabled behavior.

### Task 2: BPF map for allowlist + default_deny

**Files:** `internal/netmonitor/ebpf/connect.bpf.c`, `internal/netmonitor/ebpf/program.go`, `internal/netmonitor/ebpf/attach_linux.go`

Steps:
1) Add LRU hash map `allowlist` keyed `{u8 family; u16 dport; u8 addr[16]}` value u8 allow.
2) Add scalar map `default_deny` (u8).
3) Update connect hook: if default_deny==1 and key missing -> return -EPERM; else allow. Emit a ringbuf event with `blocked=true` to distinguish denials.
4) Rebuild CO-RE objects (x86, arm64).

### Task 3: User-space map population

**Files:** `internal/api/cgroups.go`, `internal/api/ebpf_forward.go`, `internal/netmonitor/ebpf/program.go` (helpers), `internal/netmonitor/ebpf/attach_other.go` (stubs)

Steps:
1) Add helper to populate allowlist: given []AllowedEndpoint -> clear map, set default_deny=1, insert keys.
2) On command start (cgroup hook) compute allowed endpoints from policy: check command/network rules; resolve domains to IPs (best-effort), include loopback if allowed. If DNS fails and enforce_without_dns=false, skip enforce (set default_deny=0) and log warning.
3) If population fails, disable enforce for the session and log `ebpf_enforce_disabled`.

### Task 4: Event emission and metrics

**Files:** `internal/api/ebpf_forward.go`, `internal/api/ebpf_forward.go` (extend), `internal/metrics/metrics.go`

Steps:
1) Forward blocked events (`blocked=true`) to store/broker as `net_connect_blocked` with reason=ebpf.
2) Metrics: add counters `agentsh_net_ebpf_blocked_total`, `agentsh_net_ebpf_map_load_fail_total`.
3) Ensure rdns enrichment stays optional.

### Task 5: Tests

**Files:**
- Unit: `internal/netmonitor/ebpf` (map load, key encode), `internal/api` (policy → endpoints), `internal/metrics` (new counters)
- Integration (Linux-only): `internal/api/ebpf_enforce_integration_test.go`

Steps:
1) Unit test map population helper with synthetic IPs.
2) Integration: enable enforce, allow localhost only, attempt external connect -> expect -EPERM and `net_connect_blocked` event; allowed connect succeeds.
3) Verify fallback when DNS fails and enforce_without_dns=false: default_deny unset and connect not blocked.

### Task 6: Docs

**Files:** `docs/plans/2025-12-19-ebpf-enforcement-design.md` (this), `README.md`/`config.yml` section update.

Steps:
1) Document new flags and behavior, note Linux-only and DNS caveats.

### Task 7: Release hygiene

Steps:
1) Rebuild CO-RE objects for x86/arm64, commit artifacts.
2) Run `go test ./...` and `make smoke`.
3) Update changelog/release notes.

---

Ready to execute? If yes, choose execution mode:
1) Subagent-driven here, or 2) parallel session with executing-plans.
