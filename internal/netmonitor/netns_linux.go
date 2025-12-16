//go:build linux

package netmonitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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

func SetupNetNS(ctx context.Context, nsName string, subnetCIDR string, hostIf string, nsIf string, hostIPCIDR string, nsIPCIDR string, proxyTCPPort int, dnsUDPPort int) (*NetNS, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("transparent netns requires root (euid=%d)", os.Geteuid())
	}

	if err := run(ctx, "ip", "netns", "add", nsName); err != nil {
		return nil, err
	}
	cleanup := func() {
		_ = run(ctx, "ip", "netns", "del", nsName)
		_ = run(ctx, "ip", "link", "del", hostIf)
	}

	// veth pair.
	if err := run(ctx, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", nsIf); err != nil {
		cleanup()
		return nil, err
	}
	if err := run(ctx, "ip", "link", "set", nsIf, "netns", nsName); err != nil {
		cleanup()
		return nil, err
	}
	if err := run(ctx, "ip", "addr", "add", hostIPCIDR, "dev", hostIf); err != nil {
		cleanup()
		return nil, err
	}
	if err := run(ctx, "ip", "link", "set", hostIf, "up"); err != nil {
		cleanup()
		return nil, err
	}

	// Inside netns: bring up lo + veth, assign IP and route.
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up"); err != nil {
		cleanup()
		return nil, err
	}
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "addr", "add", nsIPCIDR, "dev", nsIf); err != nil {
		cleanup()
		return nil, err
	}
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "link", "set", nsIf, "up"); err != nil {
		cleanup()
		return nil, err
	}

	hostIP := stripCIDR(hostIPCIDR)
	if err := run(ctx, "ip", "netns", "exec", nsName, "ip", "route", "add", "default", "via", hostIP); err != nil {
		cleanup()
		return nil, err
	}

	// Enable forwarding.
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)

	// Host NAT for the session subnet.
	_ = run(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnetCIDR, "-j", "MASQUERADE")
	_ = run(ctx, "iptables", "-A", "FORWARD", "-s", subnetCIDR, "-j", "ACCEPT")
	_ = run(ctx, "iptables", "-A", "FORWARD", "-d", subnetCIDR, "-j", "ACCEPT")

	// Netns DNAT outbound to host-side interceptors.
	hostTCP := fmt.Sprintf("%s:%d", hostIP, proxyTCPPort)
	hostDNS := fmt.Sprintf("%s:%d", hostIP, dnsUDPPort)
	// Avoid rewriting traffic destined to the host veth IP.
	_ = run(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-A", "OUTPUT", "-d", hostIP, "-j", "RETURN")
	_ = run(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-A", "OUTPUT", "-d", "127.0.0.0/8", "-j", "RETURN")
	_ = run(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "DNAT", "--to-destination", hostTCP)
	_ = run(ctx, "ip", "netns", "exec", nsName, "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", hostDNS)

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

func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

