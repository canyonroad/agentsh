package redirect

import (
	"net"
	"sync"
	"time"
)

// HostnameEntry stores resolved IPs for a hostname
type HostnameEntry struct {
	Hostname  string
	IPs       []net.IP
	ExpiresAt time.Time
}

// CorrelationMap maps hostnames to IPs and vice versa for connect redirect matching
type CorrelationMap struct {
	mu           sync.RWMutex
	hostnameToIP map[string]*HostnameEntry
	ipToHostname map[string]string // IP string -> hostname
	ttl          time.Duration
}

// NewCorrelationMap creates a new correlation map with the given TTL
func NewCorrelationMap(ttl time.Duration) *CorrelationMap {
	return &CorrelationMap{
		hostnameToIP: make(map[string]*HostnameEntry),
		ipToHostname: make(map[string]string),
		ttl:          ttl,
	}
}

// AddResolution records a DNS resolution
func (m *CorrelationMap) AddResolution(hostname string, ips []net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry := &HostnameEntry{
		Hostname:  hostname,
		IPs:       ips,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	m.hostnameToIP[hostname] = entry

	for _, ip := range ips {
		m.ipToHostname[ip.String()] = hostname
	}
}

// LookupHostname returns the hostname for an IP address
func (m *CorrelationMap) LookupHostname(ip net.IP) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostname, ok := m.ipToHostname[ip.String()]
	if !ok {
		return "", false
	}

	// Check if entry is still valid
	entry, exists := m.hostnameToIP[hostname]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return "", false
	}

	return hostname, true
}

// Cleanup removes expired entries
func (m *CorrelationMap) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for hostname, entry := range m.hostnameToIP {
		if now.After(entry.ExpiresAt) {
			for _, ip := range entry.IPs {
				delete(m.ipToHostname, ip.String())
			}
			delete(m.hostnameToIP, hostname)
		}
	}
}
