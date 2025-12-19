# eBPF Network Tracing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add optional cgroup-based eBPF network tracing for agentsh sessions to observe outbound connects (and optionally UDP) without requiring a proxy, with clear fallback when unsupported.

**Architecture:** On session start, reuse/extend the per-session cgroup and attach CO-RE eBPF programs to cgroup connect hooks. A userspace collector reads ring-buffer events, enriches them with session/command IDs, and emits them into the existing event pipeline. A config flag enables/forces the feature; startup auto-disables on unsupported kernels and logs an event. Proxy remains the fallback path.

**Tech Stack:** Go 1.25+, Linux cgroup v2, libbpf CO-RE object (embedded), cilium/ebpf or libbpfgo, ring buffer, existing agentsh store/broker.

### Task 1: Wire config + capability detection

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`
- Modify: `config.yml` sample
- Create: `internal/netmonitor/ebpf/capability.go`

**Steps:**
1) Add `sandbox.network.ebpf.enabled` and `required` flags to config structs/defaults + sample config.  
2) Implement capability check: kernel >=5.8, BPF/BTF present, cgroup v2, CAP_BPF/CAP_SYS_ADMIN.  
3) Unit tests to cover defaults and env override path.

### Task 2: Build/ship BPF program

**Files:**
- Create: `internal/netmonitor/ebpf/connect.bpf.c` (or `.rs` if using aya) and generated `connect_bpfel.o` (CO-RE)
- Create: `internal/netmonitor/ebpf/program.go` (loader)

**Steps:**
1) Write minimal BPF: attach to `cgroup/connect4` and `connect6`; emit {pid,tgid,sock_cookie,addr,port,proto}. Optionally UDP sendmsg hook behind a compile flag.  
2) Integrate with Go via cilium/ebpf or libbpfgo; embed object with `//go:embed`.  
3) Unit test (build-tag linux) to load/unload on supported kernels; skip otherwise.

### Task 3: Session cgroup lifecycle + attach

**Files:**
- Modify: `internal/api/app.go` (session create/cleanup)
- Modify: `internal/api/cgroups.go`
- Create: `internal/netmonitor/ebpf/attach.go`

**Steps:**
1) Ensure each session gets a dedicated cgroup path (reuse limits base path).  
2) On session start, if ebpf enabled and supported, attach programs to the session cgroup.  
3) On session destroy/expire, detach and cleanup; emit `ebpf_attached` / `ebpf_unavailable` events.

### Task 4: Userspace collector + event emit

**Files:**
- Modify: `internal/netmonitor/ebpf/collector.go` (new)
- Modify: `internal/netmonitor/proxy.go` (optional tagging reuse)  
- Modify: `internal/api/core.go` (hook into broker/store)

**Steps:**
1) Start a goroutine per session (or shared) reading ring buffer; map socket cookie -> session/command using lookup maps (pid->session via cgroup membership).  
2) Emit `net_connect` events with domain/ip/port and policy info (policy check optional: reuse existing engine by calling CheckNetworkIP).  
3) Handle backpressure: drop counters + metrics.  
4) Tests: fake ring-buffer feeder to ensure events surface with session/command IDs.

### Task 5: Fallback and metrics

**Files:**
- Modify: `internal/metrics` to add counters for ebpf drops/attach failures.  
- Modify: `internal/api/app.go` to log and downgrade to proxy when ebpf disabled or fails (unless required).  
- Update docs: `docs/` README section on network monitoring.

### Task 6: End-to-end tests (Linux-only)

**Files:**
- Add: `internal/netmonitor/ebpf/ebpf_integration_test.go` (build-tag linux && ebpf)  
- Add: CI job note (if CI supports BPF) otherwise mark skipped with clear reason.

**Steps:**
1) Spawn session, run `curl 1.1.1.1:80` (or nc), assert a `net_connect` event appears with correct port.  
2) Ensure feature disables cleanly when `enabled=false` and when capability missing (simulated via env flag).  
3) Verify proxy still works when ebpf disabled.

### Task 7: Release hygiene

**Files:**
- Update: `docs/plans/CHANGELOG` or release notes  
- Optional: bump version after merge

**Steps:**
1) Run `go test ./...` and `gofmt`/`staticcheck` if available.  
2) Document new config flags and support matrix in README.

---

Ready to execute? If yes, choose execution mode:  
1) Subagent-driven in this session (recommended), or  
2) Separate session with executing-plans.  
