//go:build windows

package windows

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/policy"
)

// Network implements platform.NetworkInterceptor for Windows.
// Supports WinDivert for full traffic redirection or WFP for monitoring/blocking.
type Network struct {
	available      bool
	implementation string
	hasWinDivert   bool
	hasWFP         bool
	mu             sync.Mutex
	configured     bool
	config         platform.NetConfig
	proxyPort      int
	dnsPort        int
	stopChan       chan struct{}
	windivert      *WinDivertHandle
	natTable       *NATTable
	driverClient   *DriverClient

	// Policy engine and DNS cache for connect-level redirect support
	policyEngine *policy.Engine
	dnsCache     *netmonitor.DNSCache
}

// NewNetwork creates a new Windows network interceptor.
func NewNetwork() *Network {
	n := &Network{
		stopChan: make(chan struct{}),
	}
	n.hasWinDivert = n.checkWinDivert()
	n.hasWFP = true // WFP is always available on Windows Vista+
	n.available = n.hasWinDivert || n.hasWFP
	n.implementation = n.detectImplementation()
	return n
}

// checkWinDivert checks if WinDivert is available.
func (n *Network) checkWinDivert() bool {
	// Check for WinDivert driver
	paths := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "WinDivert.sys"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "WinDivert64.sys"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Also check for WinDivert DLL in current directory or system
	dllPaths := []string{
		"WinDivert.dll",
		filepath.Join(os.Getenv("SystemRoot"), "System32", "WinDivert.dll"),
	}

	for _, path := range dllPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// detectImplementation returns the best available network implementation.
func (n *Network) detectImplementation() string {
	if n.hasWinDivert {
		return "windivert"
	}
	if n.hasWFP {
		return "wfp"
	}
	return "none"
}

// Available returns whether network interception is available.
func (n *Network) Available() bool {
	return n.available
}

// Implementation returns the network implementation name.
func (n *Network) Implementation() string {
	return n.implementation
}

// HasWinDivert returns whether WinDivert is available.
func (n *Network) HasWinDivert() bool {
	return n.hasWinDivert
}

// HasWFP returns whether WFP is available (always true on Vista+).
func (n *Network) HasWFP() bool {
	return n.hasWFP
}

// CanRedirectTraffic returns whether traffic can be transparently redirected.
// Only WinDivert supports transparent redirection; WFP can only block/allow.
func (n *Network) CanRedirectTraffic() bool {
	return n.hasWinDivert
}

// Setup configures network interception.
// Call SetDriverClient() before Setup() if process-aware filtering is needed.
// With WinDivert: Full traffic capture and redirection to proxy.
// With WFP only: Blocking/allowing connections without transparent proxy.
func (n *Network) Setup(config platform.NetConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.config = config
	n.proxyPort = config.ProxyPort
	if n.proxyPort == 0 {
		n.proxyPort = 8080
	}
	n.dnsPort = config.DNSPort
	if n.dnsPort == 0 {
		n.dnsPort = 5353
	}

	var err error
	if n.hasWinDivert {
		err = n.setupWinDivert()
	} else if n.hasWFP {
		err = n.setupWFP()
	} else {
		return fmt.Errorf("no network interception method available")
	}

	if err != nil {
		return err
	}

	n.configured = true
	return nil
}

// setupWinDivert configures WinDivert for packet capture and redirection.
func (n *Network) setupWinDivert() error {
	n.natTable = NewNATTable(5 * time.Minute)

	var err error
	n.windivert, err = NewWinDivertHandle(n.natTable, n.config, n.driverClient, n.policyEngine, n.dnsCache)
	if err != nil {
		return fmt.Errorf("failed to create WinDivert handle: %w", err)
	}

	// Start WinDivert first
	if err := n.windivert.Start(); err != nil {
		n.windivert = nil
		n.natTable = nil
		return fmt.Errorf("failed to start WinDivert: %w", err)
	}

	// Only start cleanup goroutine after successful start
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-n.stopChan:
				return
			case <-ticker.C:
				n.natTable.Cleanup()
			}
		}
	}()

	return nil
}

// setupWFP configures Windows Filtering Platform for blocking/allowing.
func (n *Network) setupWFP() error {
	// WFP setup for network filtering (block/allow only, no redirect)
	//
	// Note: Actual implementation would use inet.af/wf library:
	//   session, err := wf.New(&wf.Options{Name: "agentsh", Dynamic: true})
	//   if err != nil { return err }
	//   sublayer := wf.Sublayer{Key: generateGUID(), Name: "agentsh network filter"}
	//   session.AddSublayer(&sublayer)
	//
	// This is a stub for cross-platform compilation.

	return nil
}

// WinDivertFilter returns the WinDivert filter string for capturing traffic.
func (n *Network) WinDivertFilter() string {
	// Capture outbound TCP (except to localhost proxy) and DNS
	return fmt.Sprintf(
		"outbound and ((tcp and tcp.DstPort != %d) or (udp and udp.DstPort == 53))",
		n.proxyPort,
	)
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.configured {
		return nil
	}

	// Close stop channel to signal goroutines
	select {
	case <-n.stopChan:
		// Already closed
	default:
		close(n.stopChan)
	}

	// Note: Real implementation would:
	// - Close WinDivert handle
	// - Or close WFP session (which removes all rules due to Dynamic flag)

	if n.windivert != nil {
		if err := n.windivert.Stop(); err != nil {
			return err
		}
		n.windivert = nil
	}

	n.configured = false
	n.stopChan = make(chan struct{})
	return nil
}

// AddBlockRule adds a rule to block traffic to a specific destination.
// Only works with WFP implementation.
func (n *Network) AddBlockRule(ip string, port int) error {
	if !n.hasWFP {
		return fmt.Errorf("WFP not available")
	}
	if !n.configured {
		return fmt.Errorf("network not configured")
	}

	// Note: Real implementation would use WFP to add a block rule:
	//   rule := &wf.Rule{
	//       Key: generateGUID(),
	//       Layer: wf.LayerALEAuthConnectV4,
	//       Action: wf.ActionBlock,
	//       Matches: []wf.Match{
	//           {Field: wf.FieldIPRemoteAddress, Op: wf.MatchEqual, Value: net.ParseIP(ip)},
	//           {Field: wf.FieldIPRemotePort, Op: wf.MatchEqual, Value: uint16(port)},
	//       },
	//   }
	//   return n.session.AddRule(rule)

	return nil
}

// AddAllowRule adds a rule to explicitly allow traffic to a destination.
// Only works with WFP implementation.
func (n *Network) AddAllowRule(ip string, port int) error {
	if !n.hasWFP {
		return fmt.Errorf("WFP not available")
	}
	if !n.configured {
		return fmt.Errorf("network not configured")
	}

	// Note: Similar to AddBlockRule but with wf.ActionPermit

	return nil
}

// NATTable returns the NAT table for proxy lookup.
func (n *Network) NATTable() *NATTable {
	return n.natTable
}

// WinDivert returns the WinDivert handle for session PID management.
func (n *Network) WinDivert() *WinDivertHandle {
	return n.windivert
}

// SetDriverClient sets the driver client for process event notifications.
// This must be called BEFORE Setup() if process-aware filtering is needed.
// If not set, WinDivert will still work but won't track session PIDs.
func (n *Network) SetDriverClient(client *DriverClient) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.driverClient = client
}

// SetPolicyEngine sets the policy engine for connect-level redirect evaluation.
// This must be called BEFORE Setup() if redirect support is needed.
func (n *Network) SetPolicyEngine(engine *policy.Engine) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.policyEngine = engine
}

// SetDNSCache sets the DNS cache for hostname correlation.
// This enables looking up hostnames from destination IPs for redirect evaluation.
// This must be called BEFORE Setup() if redirect support is needed.
func (n *Network) SetDNSCache(cache *netmonitor.DNSCache) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dnsCache = cache
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
