//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Network implements platform.NetworkInterceptor for macOS using pf (packet filter).
type Network struct {
	available      bool
	implementation string
	mu             sync.Mutex
	configured     bool
	config         platform.NetConfig
	anchorName     string
	rulesFile      string
}

// NewNetwork creates a new macOS network interceptor.
func NewNetwork() *Network {
	n := &Network{
		anchorName: "com.agentsh",
		rulesFile:  "/tmp/agentsh-pf.rules",
	}
	n.available = n.checkAvailable()
	n.implementation = "pf"
	return n
}

// checkAvailable checks if pf is available.
func (n *Network) checkAvailable() bool {
	// pf is always available on macOS, check for pfctl
	_, err := exec.LookPath("pfctl")
	return err == nil
}

// Available returns whether network interception is available.
func (n *Network) Available() bool {
	return n.available
}

// Implementation returns the network implementation name.
func (n *Network) Implementation() string {
	return n.implementation
}

// Setup configures network interception using pf.
// Note: Requires root privileges to modify pf rules.
func (n *Network) Setup(config platform.NetConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if os.Geteuid() != 0 {
		return fmt.Errorf("pf requires root access. Run with: sudo agentsh server")
	}

	n.config = config

	// Generate pf rules
	rules := n.generatePFRules()

	// Write rules to temp file
	if err := os.WriteFile(n.rulesFile, []byte(rules), 0600); err != nil {
		return fmt.Errorf("failed to write pf rules: %w", err)
	}

	// Load rules into anchor
	loadCmd := exec.Command("pfctl", "-a", n.anchorName, "-f", n.rulesFile)
	if output, err := loadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to load pf rules: %w (output: %s)", err, string(output))
	}

	// Enable pf if not already enabled
	enableCmd := exec.Command("pfctl", "-e")
	// Ignore "already enabled" error
	enableCmd.Run()

	n.configured = true
	return nil
}

// generatePFRules creates pf rules for traffic redirection.
func (n *Network) generatePFRules() string {
	proxyPort := n.config.ProxyPort
	if proxyPort == 0 {
		proxyPort = 8080
	}
	dnsPort := n.config.DNSPort
	if dnsPort == 0 {
		dnsPort = 5353
	}

	return fmt.Sprintf(`# agentsh network interception rules
# Anchor: %s

# Redirect outbound TCP to transparent proxy
rdr pass on lo0 proto tcp from any to any port 1:65535 -> 127.0.0.1 port %d

# Redirect DNS to DNS proxy
rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port %d

# Required for rdr to work
pass out quick on lo0 all
`, n.anchorName, proxyPort, dnsPort)
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.configured {
		return nil
	}

	// Flush the anchor rules
	flushCmd := exec.Command("pfctl", "-a", n.anchorName, "-F", "all")
	if output, err := flushCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to flush pf rules: %w (output: %s)", err, string(output))
	}

	// Clean up rules file
	os.Remove(n.rulesFile)

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
