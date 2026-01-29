//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/netmonitor/redirect"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// ConnectEvent matches the struct emitted by the BPF program.
type ConnectEvent struct {
	TsNs     uint64
	Cookie   uint64
	PID      uint32
	TGID     uint32
	Sport    uint16
	Dport    uint16
	Family   uint8
	Protocol uint8
	_        [6]byte
	DstIPv4  uint32
	DstIPv6  [16]byte
	Blocked  uint8
	_pad     [7]byte
}

// Collector reads events from the BPF ring buffer.
type Collector struct {
	mu     sync.Mutex
	rd     *ringbuf.Reader
	events chan ConnectEvent
	done   chan struct{}

	onDrop func()

	// Connect redirect integration
	policyEngine   *policy.Engine
	correlationMap *redirect.CorrelationMap
	onRedirect     func(*events.ConnectRedirectEvent)
}

// StartCollector starts reading events from the "events" ring buffer map.
// Caller is responsible for closing the returned collector.
func StartCollector(coll *ebpf.Collection, bufSize int) (*Collector, error) {
	if coll == nil {
		return nil, errors.New("collection nil")
	}
	if bufSize <= 0 {
		bufSize = 1024
	}
	m, ok := coll.Maps["events"]
	if !ok {
		return nil, errors.New("events map not found")
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, err
	}
	c := &Collector{
		rd:     rd,
		events: make(chan ConnectEvent, bufSize),
		done:   make(chan struct{}),
	}
	go c.loop()
	return c, nil
}

func (c *Collector) loop() {
	for {
		record, err := c.rd.Read()
		if err != nil {
			select {
			case <-c.done:
				return
			default:
			}
			// transient errors like ringbuf.ErrClosed handled by exit
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		var ev ConnectEvent
		if len(record.RawSample) >= 49 { // 49 bytes needed for blocked flag
			copyToEvent(&ev, record.RawSample)

			// Evaluate connect redirect if configured
			c.evaluateConnectRedirect(&ev)

			select {
			case c.events <- ev:
			default:
				if c.onDrop != nil {
					c.onDrop()
				}
			}
		}
	}
}

func copyToEvent(ev *ConnectEvent, data []byte) {
	// Layout matches struct in connect.bpf.c
	// Minimum 30 bytes required for base fields (up to Protocol at offset 29)
	if len(data) < 30 {
		return
	}
	ev.TsNs = le64(data[0:])
	ev.Cookie = le64(data[8:])
	ev.PID = le32(data[16:])
	ev.TGID = le32(data[20:])
	ev.Sport = le16(data[24:])
	ev.Dport = le16(data[26:])
	ev.Family = data[28]
	ev.Protocol = data[29]
	if len(data) >= 48 {
		copy(ev.DstIPv6[:], data[32:48]) // always copy 16 bytes
		if len(data) >= 40 {
			ev.DstIPv4 = le32(data[36:]) // overlap ok for v4
		}
	}
	if len(data) > 48 {
		ev.Blocked = data[48]
	}
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}

// Events channel for consumers.
func (c *Collector) Events() <-chan ConnectEvent { return c.events }

// SetOnDrop registers a callback invoked when an event is dropped due to backpressure.
func (c *Collector) SetOnDrop(fn func()) { c.onDrop = fn }

// Close stops reading and closes the ring buffer.
func (c *Collector) Close() error {
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return nil
	default:
		close(c.done)
	}
	c.mu.Unlock()
	_ = c.rd.Close()
	return nil
}

// SetPolicyEngine sets the policy engine for connect redirect evaluation.
func (c *Collector) SetPolicyEngine(engine *policy.Engine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policyEngine = engine
}

// SetCorrelationMap sets the correlation map for hostname lookups from IPs.
func (c *Collector) SetCorrelationMap(corrMap *redirect.CorrelationMap) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.correlationMap = corrMap
}

// SetOnRedirect sets the callback for connect redirect events.
func (c *Collector) SetOnRedirect(fn func(*events.ConnectRedirectEvent)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onRedirect = fn
}

// evaluateConnectRedirect checks if a connection should be redirected and emits an event.
func (c *Collector) evaluateConnectRedirect(ev *ConnectEvent) {
	// Get policy engine and correlation map under lock
	c.mu.Lock()
	engine := c.policyEngine
	corrMap := c.correlationMap
	onRedirect := c.onRedirect
	c.mu.Unlock()

	// Skip if redirect evaluation is not configured
	if engine == nil || onRedirect == nil {
		return
	}

	// Extract destination IP from event
	dstIP := c.extractDstIP(ev)
	if dstIP == nil {
		return
	}

	// Look up hostname from correlation map
	hostname := ""
	if corrMap != nil {
		hostname, _ = corrMap.LookupHostname(dstIP)
	}

	// If no hostname found, use IP address string
	if hostname == "" {
		hostname = dstIP.String()
	}

	// Build host:port string for evaluation
	hostPort := fmt.Sprintf("%s:%d", hostname, ev.Dport)

	// Evaluate connect redirect rules
	result := engine.EvaluateConnectRedirect(hostPort)
	if !result.Matched {
		return
	}

	// Emit connect redirect event
	redirectEvent := &events.ConnectRedirectEvent{
		Original:     hostPort,
		RedirectedTo: result.RedirectTo,
		Rule:         result.Rule,
		TLSMode:      result.TLSMode,
		Visibility:   result.Visibility,
		Message:      result.Message,
	}

	onRedirect(redirectEvent)
}

// extractDstIP extracts the destination IP from a connect event.
func (c *Collector) extractDstIP(ev *ConnectEvent) net.IP {
	if ev.Family == 2 { // AF_INET
		ip := make(net.IP, 4)
		ip[0] = byte(ev.DstIPv4)
		ip[1] = byte(ev.DstIPv4 >> 8)
		ip[2] = byte(ev.DstIPv4 >> 16)
		ip[3] = byte(ev.DstIPv4 >> 24)
		return ip
	} else if ev.Family == 10 { // AF_INET6
		ip := make(net.IP, 16)
		copy(ip, ev.DstIPv6[:])
		return ip
	}
	return nil
}
