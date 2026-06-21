//go:build linux

package netmonitor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSetupNetNS_InstallsTorLoopbackDNAT is a root-gated integration test that
// creates a real network namespace via SetupNetNS (with Tor redirect ports
// 9050 and 9150) and asserts that:
//  1. The loopback-DNAT rules for --dport 9050 and --dport 9150 exist in the
//     netns OUTPUT chain.
//  2. Both DNAT rules appear BEFORE the 127.0.0.0/8 RETURN rule (ordering
//     invariant required for force-redirect correctness).
//  3. net.ipv4.conf.all.route_localnet == 1 inside the netns.
//
// The test SKIPS cleanly (not fails) when run unprivileged or when the
// required binaries (ip, iptables) are absent.
//
// NOTE: The full app→onion-filter e2e (driving real traffic through the
// gateway) is a deferred CI/manual check and is out of scope here.
func TestSetupNetNS_InstallsTorLoopbackDNAT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for netns/iptables")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("requires 'ip' binary in PATH")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("requires 'iptables' binary in PATH")
	}

	const nsName = "agentsh-test-tordnat"
	const subnetBase = "10.250.0.0/16"

	subnetCIDR, hostIPCIDR, nsIPCIDR, hostIf, nsIf := AllocateSubnet(subnetBase, nsName)

	ctx := context.Background()

	// Best-effort pre-cleanup in case a prior run left the ns behind.
	_ = exec.CommandContext(ctx, "ip", "netns", "del", nsName).Run()
	_ = exec.CommandContext(ctx, "ip", "link", "del", hostIf).Run()

	ns, err := SetupNetNS(ctx, nsName, subnetCIDR, hostIf, nsIf, hostIPCIDR, nsIPCIDR,
		50000, 50053, []int{9050, 9150})
	if err != nil {
		t.Fatalf("SetupNetNS: %v", err)
	}
	defer func() {
		if err := ns.Close(context.Background()); err != nil {
			t.Logf("ns.Close: %v", err)
		}
	}()

	// --- Assert 1 & 2: iptables OUTPUT chain rule order ---
	out, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName,
		"iptables", "-t", "nat", "-S", "OUTPUT").Output()
	if err != nil {
		t.Fatalf("iptables -t nat -S OUTPUT: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	t.Logf("iptables nat OUTPUT rules:\n%s", bytes.TrimSpace(out))

	idx9050, idx9150, idxReturn := -1, -1, -1
	for i, line := range lines {
		switch {
		case strings.Contains(line, "--dport 9050") && strings.Contains(line, "127.0.0.1") && strings.Contains(line, "DNAT"):
			idx9050 = i
		case strings.Contains(line, "--dport 9150") && strings.Contains(line, "127.0.0.1") && strings.Contains(line, "DNAT"):
			idx9150 = i
		case strings.Contains(line, "127.0.0.0/8") && strings.Contains(line, "RETURN"):
			idxReturn = i
		}
	}

	if idx9050 < 0 {
		t.Error("missing loopback-DNAT rule for --dport 9050")
	}
	if idx9150 < 0 {
		t.Error("missing loopback-DNAT rule for --dport 9150")
	}
	if idxReturn < 0 {
		t.Error("missing 127.0.0.0/8 RETURN rule")
	}
	if t.Failed() {
		t.FailNow()
	}

	if idx9050 >= idxReturn {
		t.Errorf("--dport 9050 DNAT (line %d) must precede 127.0.0.0/8 RETURN (line %d)", idx9050, idxReturn)
	}
	if idx9150 >= idxReturn {
		t.Errorf("--dport 9150 DNAT (line %d) must precede 127.0.0.0/8 RETURN (line %d)", idx9150, idxReturn)
	}

	// --- Assert 3: route_localnet == 1 ---
	rlOut, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsName,
		"sysctl", "-n", "net.ipv4.conf.all.route_localnet").Output()
	if err != nil {
		t.Fatalf("sysctl route_localnet: %v", err)
	}
	got := strings.TrimSpace(string(rlOut))
	if got != "1" {
		t.Errorf("net.ipv4.conf.all.route_localnet = %q, want \"1\"", got)
	} else {
		t.Logf("net.ipv4.conf.all.route_localnet = %s (correct)", got)
	}

	t.Logf("all assertions passed: dnat9050@%d dnat9150@%d return@%d route_localnet=%s",
		idx9050, idx9150, idxReturn, got)

	// Diagnostic: log the AllocateSubnet output used.
	t.Logf("AllocateSubnet(%q, %q) → subnet=%s hostIPCIDR=%s nsIPCIDR=%s hostIf=%s nsIf=%s",
		subnetBase, nsName, subnetCIDR, hostIPCIDR, nsIPCIDR, hostIf, nsIf)
}
