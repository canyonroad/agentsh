//go:build linux

package netmonitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type NetNS struct {
	Name         string
	HostIfName   string
	NSIfName     string
	HostIP       string
	NSIP         string
	SubnetCIDR   string
	ProxyTCPPort int
	DNSUDPPort   int
}

// natOutputRules returns the ordered nat OUTPUT rule bodies (args after
// "OUTPUT") for the session netns. Tor SOCKS ports get a loopback DNAT inserted
// BEFORE the 127.0.0.0/8 RETURN so the app's connect(127.0.0.1:<port>) is
// steered across the veth to the host interceptor; all other loopback traffic
// is still exempted. Ordering is a correctness invariant (see Phase 3 design).
func natOutputRules(hostIP, hostTCP, hostDNS string, torRedirectPorts []int) [][]string {
	rules := [][]string{
		{"-d", hostIP, "-j", "RETURN"},
	}
	for _, p := range torRedirectPorts {
		rules = append(rules, []string{
			"-d", "127.0.0.1", "-p", "tcp", "--dport", strconv.Itoa(p),
			"-j", "DNAT", "--to-destination", hostTCP,
		})
	}
	rules = append(rules,
		[]string{"-d", "127.0.0.0/8", "-j", "RETURN"},
		[]string{"-p", "tcp", "-j", "DNAT", "--to-destination", hostTCP},
		[]string{"-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", hostDNS},
	)
	return rules
}

func SetupNetNS(ctx context.Context, nsName string, subnetCIDR string, hostIf string, nsIf string, hostIPCIDR string, nsIPCIDR string, proxyTCPPort int, dnsUDPPort int, torRedirectPorts []int) (*NetNS, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("transparent netns requires root (euid=%d)", os.Geteuid())
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return nil, fmt.Errorf("transparent netns requires 'ip' in PATH: %w", err)
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return nil, fmt.Errorf("transparent netns requires 'iptables' in PATH: %w", err)
	}

	if err := run(ctx, "ip", "netns", "add", nsName); err != nil {
		return nil, err
	}
	cleanupNS := func() {
		_ = run(ctx, "ip", "netns", "del", nsName)
		_ = run(ctx, "ip", "link", "del", hostIf)
	}

	// veth pair.
	if err := run(ctx, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", nsIf); err != nil {
		cleanupNS()
		return nil, err
	}
	if err := run(ctx, "ip", "link", "set", nsIf, "netns", nsName); err != nil {
		cleanupNS()
		return nil, err
	}
	if err := run(ctx, "ip", "addr", "add", hostIPCIDR, "dev", hostIf); err != nil {
		cleanupNS()
		return nil, err
	}
	if err := run(ctx, "ip", "link", "set", hostIf, "up"); err != nil {
		cleanupNS()
		return nil, err
	}

	// Inside netns: bring up lo + veth, assign IP and route.
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"); err != nil {
		cleanupNS()
		return nil, err
	}
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsIPCIDR, "dev", nsIf); err != nil {
		cleanupNS()
		return nil, err
	}
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", nsIf, "up"); err != nil {
		cleanupNS()
		return nil, err
	}

	hostIP := stripCIDR(hostIPCIDR)
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "route", "add", "default", "via", hostIP); err != nil {
		cleanupNS()
		return nil, err
	}

	rollback := make([]func(), 0, 8)
	rollbackAll := func() {
		for i := len(rollback) - 1; i >= 0; i-- {
			rollback[i]()
		}
	}

	// Enable forwarding (or ensure it's already on).
	if err := ensureIPForward(); err != nil {
		rollbackAll()
		cleanupNS()
		return nil, err
	}

	// Host NAT for the session subnet (required).
	if err := run(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "-j", "MASQUERADE"); err != nil {
		rollbackAll()
		cleanupNS()
		return nil, err
	}
	rollback = append(rollback, func() {
		_ = run(context.Background(), "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnetCIDR, "-j", "MASQUERADE")
	})
	if err := run(ctx, "iptables", "-A", "FORWARD", "-s", subnetCIDR, "-j", "ACCEPT"); err != nil {
		rollbackAll()
		cleanupNS()
		return nil, err
	}
	rollback = append(rollback, func() {
		_ = run(context.Background(), "iptables", "-D", "FORWARD", "-s", subnetCIDR, "-j", "ACCEPT")
	})
	if err := run(ctx, "iptables", "-A", "FORWARD", "-d", subnetCIDR, "-j", "ACCEPT"); err != nil {
		rollbackAll()
		cleanupNS()
		return nil, err
	}
	rollback = append(rollback, func() {
		_ = run(context.Background(), "iptables", "-D", "FORWARD", "-d", subnetCIDR, "-j", "ACCEPT")
	})

	// Netns DNAT outbound to host-side interceptors.
	hostTCP := fmt.Sprintf("%s:%d", hostIP, proxyTCPPort)
	hostDNS := fmt.Sprintf("%s:%d", hostIP, dnsUDPPort)
	if len(torRedirectPorts) > 0 {
		// Permit routing of loopback-destined packets so the Tor SOCKS DNAT can
		// forward them across the veth to the host interceptor.
		if err := run(ctx, "ip", "netns", "exec", nsName, "sysctl", "-w", "net.ipv4.conf.all.route_localnet=1"); err != nil {
			rollbackAll()
			cleanupNS()
			return nil, err
		}
	}
	for _, body := range natOutputRules(hostIP, hostTCP, hostDNS, torRedirectPorts) {
		args := append([]string{"ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-A", "OUTPUT"}, body...)
		if err := run(ctx, args[0], args[1:]...); err != nil {
			rollbackAll()
			cleanupNS()
			return nil, err
		}
	}

	return &NetNS{
		Name:         nsName,
		HostIfName:   hostIf,
		NSIfName:     nsIf,
		HostIP:       hostIP,
		NSIP:         stripCIDR(nsIPCIDR),
		SubnetCIDR:   subnetCIDR,
		ProxyTCPPort: proxyTCPPort,
		DNSUDPPort:   dnsUDPPort,
	}, nil
}

func (n *NetNS) Close(ctx context.Context) error {
	if n == nil {
		return nil
	}
	_ = run(ctx, "ip", "netns", "del", n.Name)
	_ = run(ctx, "ip", "link", "del", n.HostIfName)
	// Best-effort cleanup NAT/FORWARD rules.
	_ = run(ctx, "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", n.SubnetCIDR, "-j", "MASQUERADE")
	_ = run(ctx, "iptables", "-D", "FORWARD", "-s", n.SubnetCIDR, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "-D", "FORWARD", "-d", n.SubnetCIDR, "-j", "ACCEPT")
	return nil
}

func run(ctx context.Context, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureIPForward() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	b, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("failed to enable ip_forward (%s): %w", path, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(after)) != "1" {
		return fmt.Errorf("ip_forward not enabled (%s)", path)
	}
	return nil
}

func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}
