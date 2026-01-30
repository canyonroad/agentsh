package redirect

import (
	"net"
	"testing"
	"time"
)

func TestCorrelationMap_AddAndLookup(t *testing.T) {
	m := NewCorrelationMap(time.Minute)

	ips := []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")}
	m.AddResolution("api.anthropic.com", ips)

	// Lookup by first IP
	hostname, ok := m.LookupHostname(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Error("expected to find hostname for 10.0.0.1")
	}
	if hostname != "api.anthropic.com" {
		t.Errorf("expected api.anthropic.com, got %s", hostname)
	}

	// Lookup by second IP
	hostname, ok = m.LookupHostname(net.ParseIP("10.0.0.2"))
	if !ok {
		t.Error("expected to find hostname for 10.0.0.2")
	}
	if hostname != "api.anthropic.com" {
		t.Errorf("expected api.anthropic.com, got %s", hostname)
	}

	// Lookup unknown IP
	_, ok = m.LookupHostname(net.ParseIP("192.168.1.1"))
	if ok {
		t.Error("expected not to find hostname for unknown IP")
	}
}

func TestCorrelationMap_Expiry(t *testing.T) {
	m := NewCorrelationMap(10 * time.Millisecond)

	ips := []net.IP{net.ParseIP("10.0.0.1")}
	m.AddResolution("api.anthropic.com", ips)

	// Should find immediately
	_, ok := m.LookupHostname(net.ParseIP("10.0.0.1"))
	if !ok {
		t.Error("expected to find hostname immediately after adding")
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	// Should not find after expiry
	_, ok = m.LookupHostname(net.ParseIP("10.0.0.1"))
	if ok {
		t.Error("expected not to find hostname after expiry")
	}
}

func TestCorrelationMap_Cleanup(t *testing.T) {
	m := NewCorrelationMap(10 * time.Millisecond)

	ips := []net.IP{net.ParseIP("10.0.0.1")}
	m.AddResolution("api.anthropic.com", ips)

	time.Sleep(20 * time.Millisecond)
	m.Cleanup()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.hostnameToIP) != 0 {
		t.Errorf("expected hostnameToIP to be empty after cleanup, got %d entries", len(m.hostnameToIP))
	}
	if len(m.ipToHostname) != 0 {
		t.Errorf("expected ipToHostname to be empty after cleanup, got %d entries", len(m.ipToHostname))
	}
}
