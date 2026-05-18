# eBPF network tracing & enforcement

agentsh can observe outbound TCP connections and, optionally, enforce per-session allowlists in-kernel using cgroup eBPF programs. This complements the proxy / transparent modes and is Linux-only.

## What is captured
- `net_connect` events for every TCP connect; includes pid/tgid, sport/dport, dst IP, family, and optional `rdns`.
- `net_connect_blocked` when enforcement denies a connect in BPF.

## Enforcement model
- If `sandbox.network.ebpf.enforce=true`, the BPF program default-denies and allows only:
  - Loopback (127.0.0.1/::1)
  - Policy-derived exact domains (resolved to IPs) and CIDRs (port-aware)
- Wildcard domains stay non-strict (default-deny disabled); an event `ebpf_enforce_non_strict` is emitted.
- Domains are resolved and refreshed on a jittered interval bounded by `dns_max_ttl_seconds`; DNS cache is bounded.

## `agentsh wrap`

On Linux, `agentsh wrap` attaches the wrapped agent process tree to cgroup eBPF before `agentsh-unixwrap` is acknowledged and allowed to exec the real agent. This protects wrapped subprocesses even when they remove `HTTP_PROXY`, `HTTPS_PROXY`, or related proxy environment variables.

`sandbox.cgroups.enabled: true` is optional for this path. When `cgroups.enabled: false` and `ebpf.enabled: true`, agentsh probes the host for "attach-only" cgroup feasibility (mkdir + attach pid without enabling resource controllers) and uses that path if available. If `sandbox.network.ebpf.required: true` and neither nested/top-level nor attach-only cgroup is reachable, server startup fails closed.

Domain rules are still enforced by resolving literal domains to IP/port map entries in userspace. eBPF does not match domain strings in the kernel. Wildcard domains, shared CDN IPs, cached DNS answers, hosts-file entries, and DNS-over-HTTPS keep the same caveats described above.

## Configuration (config.yml)

> **`sandbox.cgroups.enabled: true` is optional for eBPF enforcement.**
> The eBPF cgroup_connect program attaches to a per-session cgroup created
> by agentsh. When `cgroups.enabled: false` and `ebpf.{enabled,enforce}: true`,
> agentsh probes the host for "attach-only" cgroup feasibility (mkdir +
> attach pid without enabling resource controllers) and uses that path
> if available. Set `cgroups.enabled: true` only if you also want resource
> limits (memory, cpu, pids). For strict enforcement guarantees, set
> `sandbox.network.ebpf.required: true` — startup fails closed if neither
> path works.

```yaml
sandbox:
  cgroups:
    enabled: false               # optional; set true only for memory/cpu/pids limits
  network:
    ebpf:
      enabled: true                # turn on connect tracing
      enforce: true                # default-deny unless allowed
      enforce_without_dns: false   # if true, keep default-deny even when DNS fails
      resolve_rdns: false          # reverse DNS on events
      dns_refresh_seconds: 60      # 0 disables refresh
      dns_max_ttl_seconds: 60      # cap for cached TTLs
      map_allow_entries: 2048      # allowlist map size (0 = embedded default)
      map_deny_entries: 2048       # denylist map size
      map_lpm_entries: 2048        # CIDR LPM map size
      map_lpm_deny_entries: 2048   # deny CIDR LPM map size
      map_default_entries: 1024    # default_deny map size
      # Map overrides apply at startup (process-wide); restart to change.
```

## Policy mapping
Use `network_rules` in policy:
```yaml
network_rules:
  - name: allow-api
    domains: ["api.example.com"]
    ports: [443]
    decision: allow
  - name: allow-cidr
    cidrs: ["10.0.0.0/8"]
    ports: [443]
    decision: allow
  - name: deny-badhost
    domains: ["badhost.example.com"]
    decision: deny
```
Wildcard domains (`*.example.com`) disable strict/default-deny.

## Debugging and observability
- `GET /debug/ebpf` returns map overrides/defaults, last-populated map counts (best-effort, not live occupancy), and DNS cache stats.
- `go test -tags=integration ./internal/netmonitor/ebpf` runs a minimal attach/enforce check (requires root + cgroup v2).

## Platform notes
- Linux 5.4+ (5.15+ recommended); enforcement requires root and cgroup v2.
- Maps are shared process-wide; map size overrides are set once at startup.

### Stock Docker host-side prerequisite for resource limits (optional)

If you set `sandbox.cgroups.enabled: true` to get memory/cpu/pids
resource limits, stock Docker has an extra step: container scopes ship
with empty `cgroup.subtree_control`, and writing `+memory` to it from
inside the container returns `ENOTSUP` even with `CAP_SYS_ADMIN`. The
agentsh cgroup manager will fail to enable the `memory` controller and
refuse commands that request resource limits. `agentsh detect` surfaces
this as:

```
RESOURCE LIMITS
  cgroups_v2_resource_limits  ✗  unavailable: enable controller "memory" failed:
                                 write /sys/fs/cgroup/cgroup.subtree_control:
                                 operation not supported
```

Fix on the host:

```ini
# /etc/systemd/system/docker.service.d/cgroup-delegate.conf
[Service]
Delegate=memory pids cpu
```

Then `systemctl daemon-reload && systemctl restart docker` and rerun the
container.

**Not required for eBPF network enforcement.** With `cgroups.enabled:
false, ebpf.enabled: true`, agentsh activates attach-only mode and the
BPF cgroup_connect program runs without any controllers enabled. The
`--cap-add SYS_ADMIN --cap-add BPF -v /sys/fs/bpf:/sys/fs/bpf:rw` flags
on `docker run` are still required for the attach itself. See issue
[#343](https://github.com/canyonroad/agentsh/issues/343) for the original
reproduction and [#347](https://github.com/canyonroad/agentsh/issues/347)
for the BPF-only mode that resolved it.

**Tip:** Use `agentsh detect` to check if eBPF is available in your environment. See [Cross-Platform Notes](cross-platform.md#detecting-available-capabilities).
