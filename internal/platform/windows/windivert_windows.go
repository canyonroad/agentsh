// internal/platform/windows/windivert_windows.go
//go:build windows

package windows

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agentsh/agentsh/internal/netmonitor"
	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/williamfhe/godivert"
	"github.com/williamfhe/godivert/header"
)

// WinDivertHandle wraps godivert with session-aware filtering.
type WinDivertHandle struct {
	handle    *godivert.WinDivertHandle
	natTable  *NATTable
	proxyPort uint16
	dnsPort   uint16

	// Session PID tracking
	sessionPIDs map[uint32]bool
	pidMu       sync.RWMutex

	// Driver client for process events
	driver *DriverClient

	// Policy engine and DNS cache for connect-level redirect
	policyEngine *policy.Engine
	dnsCache     *netmonitor.DNSCache

	// Fail mode
	failMode            FailMode
	consecutiveFailures int32
	maxFailures         int32
	inFailMode          int32 // atomic bool

	// Lifecycle
	mu       sync.Mutex // protects handle and stopChan during Start/Stop
	stopChan chan struct{}
	wg       sync.WaitGroup
	running  int32 // atomic bool
}

// NewWinDivertHandle creates a new WinDivert handle.
func NewWinDivertHandle(natTable *NATTable, config platform.NetConfig, driver *DriverClient) (*WinDivertHandle, error) {
	proxyPort := uint16(config.ProxyPort)
	if proxyPort == 0 {
		proxyPort = 9080
	}
	dnsPort := uint16(config.DNSPort)
	if dnsPort == 0 {
		dnsPort = 5353
	}

	return &WinDivertHandle{
		natTable:    natTable,
		proxyPort:   proxyPort,
		dnsPort:     dnsPort,
		sessionPIDs: make(map[uint32]bool),
		driver:      driver,
		failMode:    FailModeOpen,
		maxFailures: 10,
		stopChan:    make(chan struct{}),
	}, nil
}

// baseFilter returns the WinDivert filter string.
// We capture all outbound TCP and DNS, then filter by PID in user-mode.
func (w *WinDivertHandle) baseFilter() string {
	return "outbound and (tcp or (udp and udp.DstPort == 53))"
}

// SubscribeToProcessEvents registers callbacks with the driver client.
func (w *WinDivertHandle) SubscribeToProcessEvents() {
	if w.driver == nil {
		return
	}

	w.driver.SetProcessEventHandler(func(sessionToken uint64, processId, parentId uint32, createTime uint64, isCreation bool) {
		if isCreation {
			w.AddSessionPID(processId)
		} else {
			w.RemoveSessionPID(processId)
		}
	})
}

// Start begins packet capture and redirection.
func (w *WinDivertHandle) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if atomic.LoadInt32(&w.running) == 1 {
		return fmt.Errorf("WinDivert already running")
	}

	// Subscribe to process events for PID tracking
	w.SubscribeToProcessEvents()

	var err error
	w.handle, err = godivert.NewWinDivertHandle(w.baseFilter())
	if err != nil {
		return fmt.Errorf("failed to open WinDivert handle: %w", err)
	}

	w.stopChan = make(chan struct{})
	atomic.StoreInt32(&w.running, 1)
	w.wg.Add(1)
	go w.captureLoop()

	return nil
}

// Stop halts packet capture.
func (w *WinDivertHandle) Stop() error {
	w.mu.Lock()
	if atomic.LoadInt32(&w.running) == 0 {
		w.mu.Unlock()
		return nil // Already stopped
	}
	atomic.StoreInt32(&w.running, 0)
	close(w.stopChan)
	handle := w.handle
	w.handle = nil
	w.mu.Unlock()

	w.wg.Wait()

	if handle != nil {
		return handle.Close()
	}
	return nil
}

// AddSessionPID adds a process ID to the session filter.
func (w *WinDivertHandle) AddSessionPID(pid uint32) {
	w.pidMu.Lock()
	defer w.pidMu.Unlock()
	w.sessionPIDs[pid] = true
}

// RemoveSessionPID removes a process ID from the session filter.
func (w *WinDivertHandle) RemoveSessionPID(pid uint32) {
	w.pidMu.Lock()
	defer w.pidMu.Unlock()
	delete(w.sessionPIDs, pid)

	// Also cleanup NAT entries for this PID
	w.natTable.RemoveByPID(pid)
}

// IsSessionPID checks if a PID belongs to a session.
func (w *WinDivertHandle) IsSessionPID(pid uint32) bool {
	w.pidMu.RLock()
	defer w.pidMu.RUnlock()
	return w.sessionPIDs[pid]
}

// SetPolicyEngine sets the policy engine for connect-level redirect evaluation.
func (w *WinDivertHandle) SetPolicyEngine(engine *policy.Engine) {
	w.policyEngine = engine
}

// SetDNSCache sets the DNS cache for hostname correlation.
func (w *WinDivertHandle) SetDNSCache(cache *netmonitor.DNSCache) {
	w.dnsCache = cache
}

// captureLoop is the main packet capture goroutine.
func (w *WinDivertHandle) captureLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopChan:
			return
		default:
			w.mu.Lock()
			handle := w.handle
			w.mu.Unlock()
			if handle == nil {
				return
			}
			packet, err := handle.Recv()
			if err != nil {
				w.handleError(err)
				continue
			}
			w.processPacket(packet, handle)
		}
	}
}

// processPacket handles a captured packet.
// Note: WinDivert 1.x (used by godivert) does not provide per-packet PID.
// For session-aware filtering, we rely on the minifilter driver to track
// which PIDs belong to sessions. In this implementation, we redirect all
// captured traffic and let the proxy determine if it's from a session process.
// A future upgrade to WinDivert 2.x would provide per-packet ProcessId.
func (w *WinDivertHandle) processPacket(packet *godivert.Packet, handle *godivert.WinDivertHandle) {
	// Check fail mode
	if atomic.LoadInt32(&w.inFailMode) == 1 {
		if w.failMode == FailModeOpen {
			// Let traffic through unmodified
			_, _ = handle.Send(packet) // Ignore send errors in fail mode
		}
		// FailModeClosed: drop packet (don't reinject)
		return
	}

	// Parse packet headers
	packet.ParseHeaders()

	// Without per-packet PID from WinDivert 2.x, we redirect all captured
	// outbound traffic. The proxy layer will use SO_ORIGINAL_DST equivalent
	// or the NAT table to determine the original destination.
	// For production use, consider upgrading to WinDivert 2.x or using
	// Windows Filtering Platform (WFP) which provides process context.
	w.redirectPacket(packet, handle)
}

// redirectPacket modifies packet destination to proxy.
func (w *WinDivertHandle) redirectPacket(packet *godivert.Packet, handle *godivert.WinDivertHandle) {
	srcIP := packet.SrcIP()
	srcPort, err := packet.SrcPort()
	if err != nil {
		// Can't get source port, reinject unchanged
		_, _ = handle.Send(packet) // Ignore send errors
		return
	}

	dstIP := packet.DstIP()
	dstPort, err := packet.DstPort()
	if err != nil {
		// Can't get destination port, reinject unchanged
		_, _ = handle.Send(packet) // Ignore send errors
		return
	}

	key := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)

	// Check protocol type using NextHeaderType
	nextHeader := packet.NextHeaderType()

	if nextHeader == header.TCP {
		// Check if SYN flag (new connection)
		tcpHdr, ok := packet.NextHeader.(*header.TCPHeader)
		if !ok {
			_, _ = handle.Send(packet) // Ignore send errors
			return
		}

		if tcpHdr.SYN() && !tcpHdr.ACK() {
			// Evaluate connect redirect for new connections
			redirectTo, redirectTLS, redirectSNI := w.evaluateConnectRedirect(dstIP, dstPort)

			// Store original destination in NAT table
			w.natTable.InsertWithRedirect(
				key,
				net.ParseIP(dstIP.String()),
				dstPort,
				"tcp",
				0, // PID not available in WinDivert 1.x
				redirectTo,
				redirectTLS,
				redirectSNI,
			)
		}

		// Rewrite destination to proxy
		packet.SetDstIP(net.ParseIP("127.0.0.1"))
		packet.SetDstPort(w.proxyPort)

	} else if nextHeader == header.UDP && dstPort == 53 {
		// Store original destination in NAT table
		w.natTable.InsertWithRedirect(
			key,
			net.ParseIP(dstIP.String()),
			dstPort,
			"udp",
			0, // PID not available in WinDivert 1.x
			"", "", "", // No redirect for DNS packets (handled by DNS proxy)
		)

		// Rewrite destination to DNS proxy
		packet.SetDstIP(net.ParseIP("127.0.0.1"))
		packet.SetDstPort(w.dnsPort)
	} else {
		// Not TCP or DNS UDP, reinject unchanged
		_, _ = handle.Send(packet) // Ignore send errors
		return
	}

	// Recalculate checksums and reinject
	packet.CalcNewChecksum(handle)
	_, _ = handle.Send(packet) // Ignore send errors
}

// evaluateConnectRedirect checks if a connection should be redirected.
// Returns the redirect destination, TLS mode, and SNI (all empty if no redirect).
func (w *WinDivertHandle) evaluateConnectRedirect(dstIP net.IP, dstPort uint16) (redirectTo, redirectTLS, redirectSNI string) {
	// If no policy engine or DNS cache, no redirect
	if w.policyEngine == nil || w.dnsCache == nil {
		return "", "", ""
	}

	// Look up hostname from DNS cache using destination IP
	hostname, found := w.dnsCache.LookupByIP(dstIP, time.Now())
	if !found {
		// No hostname correlation, use IP as hostname
		hostname = dstIP.String()
	}

	// Build host:port string for policy matching
	hostPort := net.JoinHostPort(hostname, strconv.Itoa(int(dstPort)))

	// Evaluate connect redirect rules
	result := w.policyEngine.EvaluateConnectRedirect(hostPort)
	if result.Matched {
		return result.RedirectTo, result.TLSMode, result.SNI
	}

	return "", "", ""
}

// handleError handles packet capture errors.
func (w *WinDivertHandle) handleError(err error) {
	failures := atomic.AddInt32(&w.consecutiveFailures, 1)
	if failures >= w.maxFailures && atomic.LoadInt32(&w.inFailMode) == 0 {
		atomic.StoreInt32(&w.inFailMode, 1)
	}
}
