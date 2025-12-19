package api

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

var (
	resolveDomainWithTTL = resolveDomainTTL
)

// buildAllowedEndpoints converts policy/network rules into ebpf allowlist entries and CIDRs.
// Best-effort: expands allow network rules into concrete IP/port tuples and prefix matches.
// Returns: allow entries, allow cidrs, deny entries, deny cidrs, strict flag, hasDomains flag, ttlHint (min TTL observed, 0 if none).
func buildAllowedEndpoints(p *policy.Engine, maxTTL time.Duration) ([]ebpf.AllowKey, []ebpf.AllowCIDR, []ebpf.AllowKey, []ebpf.AllowCIDR, bool, bool, time.Duration) {
	if p == nil {
		return nil, nil, nil, nil, false, false, 0
	}

	var (
		out            []ebpf.AllowKey
		cidrOut        []ebpf.AllowCIDR
		denyOut        []ebpf.AllowKey
		denyCIDRs      []ebpf.AllowCIDR
		canDefaultDeny = true
		hasDomains     = false
		ttlHint        time.Duration
	)
	add := func(ip net.IP, port uint16) {
		if ip == nil {
			return
		}
		if ip4 := ip.To4(); ip4 != nil {
			var k ebpf.AllowKey
			k.Family = 2
			k.Dport = port
			copy(k.Addr[:4], ip4)
			out = append(out, k)
			return
		}
		ip6 := ip.To16()
		if ip6 == nil {
			return
		}
		var k ebpf.AllowKey
		k.Family = 10
		k.Dport = port
		copy(k.Addr[:], ip6)
		out = append(out, k)
	}

	addV4 := func(ip net.IP, port uint16) {
		var k ebpf.AllowKey
		k.Family = 2
		k.Dport = port
		copy(k.Addr[:4], ip.To4())
		out = append(out, k)
	}
	addV6 := func(ip net.IP, port uint16) {
		var k ebpf.AllowKey
		k.Family = 10
		k.Dport = port
		copy(k.Addr[:], ip.To16())
		out = append(out, k)
	}

	// Always allow loopback; port 0 means any.
	addV4(net.ParseIP("127.0.0.1"), 0)
	addV6(net.ParseIP("::1"), 0)

	// Expand allow network rules.
	for _, r := range p.NetworkRules() {
		isAllow := strings.EqualFold(r.Decision, string(types.DecisionAllow))
		isDeny := strings.EqualFold(r.Decision, string(types.DecisionDeny))
		if !isAllow && !isDeny {
			continue
		}
		ports := r.Ports
		if len(ports) == 0 {
			ports = []int{0} // any port
		}

		// Domains with wildcards can't be expanded precisely; mark non-strict.
		for _, d := range r.Domains {
			if strings.ContainsAny(d, "*?[") {
				if isAllow {
					canDefaultDeny = false
				}
				hasDomains = true
			}
		}

		// Literal domains -> resolve best-effort.
		for _, d := range r.Domains {
			if strings.ContainsAny(d, "*?[") {
				continue
			}
			hasDomains = true
			ips, ttl := resolveDomainWithTTL(d, maxTTL)
			if ttlHint == 0 || (ttl > 0 && ttl < ttlHint) {
				ttlHint = ttl
			}
			for _, ip := range ips {
				for _, port := range ports {
					if isAllow {
						add(ip, uint16(port))
					} else {
						if ip4 := ip.To4(); ip4 != nil {
							var k ebpf.AllowKey
							k.Family = 2
							k.Dport = uint16(port)
							copy(k.Addr[:4], ip4)
							denyOut = append(denyOut, k)
						} else {
							var k ebpf.AllowKey
							k.Family = 10
							k.Dport = uint16(port)
							copy(k.Addr[:], ip.To16())
							denyOut = append(denyOut, k)
						}
					}
				}
			}
			if len(ips) == 0 && isAllow {
				canDefaultDeny = false
			}
		}

		// CIDR entries could be approximated by skipping; do nothing but keep non-strict flag.
		for _, cidr := range r.CIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil || ipnet == nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			for _, port := range ports {
				var c ebpf.AllowCIDR
				if ipnet.IP.To4() != nil {
					c.Family = 2
					c.PrefixLen = uint32(ones)
					copy(c.Addr[:4], ipnet.IP.To4())
				} else {
					c.Family = 10
					c.PrefixLen = uint32(ones)
					copy(c.Addr[:], ipnet.IP.To16())
				}
				c.Dport = uint16(port)
				if isAllow {
					cidrOut = append(cidrOut, c)
				} else {
					denyCIDRs = append(denyCIDRs, c)
				}
			}
		}

		// If there were no domains or cidrs, still allow by port-only wildcard (skip; too broad).
	}

	// Deduplicate entries.
	out = dedupAllowKeys(out)
	cidrOut = dedupCIDRs(cidrOut)
	denyOut = dedupAllowKeys(denyOut)
	denyCIDRs = dedupCIDRs(denyCIDRs)

	// Enable default-deny only if coverage is exact.
	return out, cidrOut, denyOut, denyCIDRs, canDefaultDeny && (len(out) > 0 || len(cidrOut) > 0), hasDomains, ttlHint
}

func dedupAllowKeys(in []ebpf.AllowKey) []ebpf.AllowKey {
	seen := make(map[string]struct{}, len(in))
	out := make([]ebpf.AllowKey, 0, len(in))
	for _, k := range in {
		key := fmt.Sprintf("%d-%d-%x", k.Family, k.Dport, k.Addr)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, k)
	}
	return out
}

func dedupCIDRs(in []ebpf.AllowCIDR) []ebpf.AllowCIDR {
	seen := make(map[string]struct{}, len(in))
	out := make([]ebpf.AllowCIDR, 0, len(in))
	for _, k := range in {
		key := fmt.Sprintf("%d-%d-%x", k.Family, k.PrefixLen, k.Addr)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, k)
	}
	return out
}
