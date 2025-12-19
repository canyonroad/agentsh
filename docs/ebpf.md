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

## Configuration (config.yml)
```yaml
sandbox:
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
