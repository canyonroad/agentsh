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

This requires `sandbox.cgroups.enabled: true`. If `sandbox.network.ebpf.required: true` and cgroups or eBPF setup cannot complete, wrap setup fails before the real agent starts.

Domain rules are still enforced by resolving literal domains to IP/port map entries in userspace. eBPF does not match domain strings in the kernel. Wildcard domains, shared CDN IPs, cached DNS answers, hosts-file entries, and DNS-over-HTTPS keep the same caveats described above.

## Configuration (config.yml)

> **Prerequisite:** the eBPF runtime is attached inside the cgroup-setup
> path, so `sandbox.cgroups.enabled: true` is required. With `enabled:
> true` (or `enforce: true`) but `cgroups.enabled: false`, the eBPF
> backend is silently skipped — the server logs a startup `WARN` line
> (`ebpf: enforcement configured but inactive`). Setting `required:
> true` upgrades the silent skip to a hard startup error.

```yaml
sandbox:
  cgroups:
    enabled: true                # REQUIRED for eBPF activation
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

### Stock Docker host-side prerequisite

`sandbox.cgroups.enabled: true` is necessary but on stock Docker it isn't
sufficient — Docker delegates a cgroup scope to each container but ships
`cgroup.subtree_control` empty, and writing `+memory` to it from inside
the container returns `ENOTSUP` even with `CAP_SYS_ADMIN`. The agentsh
cgroup manager fails to enable the `memory` controller and the eBPF
attach path never runs. `agentsh detect` surfaces this as:

```
RESOURCE LIMITS
  cgroups-v2  -  unavailable: enable controller "memory" failed:
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
container. `--cap-add SYS_ADMIN --cap-add BPF -v /sys/fs/bpf:/sys/fs/bpf:rw`
on `docker run` are also required for the attach itself. See issue
[#343](https://github.com/canyonroad/agentsh/issues/343) for the full
reproduction.

**Tip:** Use `agentsh detect` to check if eBPF is available in your environment. See [Cross-Platform Notes](cross-platform.md#detecting-available-capabilities).
