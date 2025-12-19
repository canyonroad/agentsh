package api

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsEntry struct {
	ips    []net.IP
	expiry time.Time
}

var (
	dnsMu     sync.Mutex
	dnsCache  = make(map[string]dnsEntry)
	dnsMaxEnt = 1024
	dnsClient = &dns.Client{
		Net:          "udp",
		Timeout:      300 * time.Millisecond,
		DialTimeout:  300 * time.Millisecond,
		ReadTimeout:  300 * time.Millisecond,
		WriteTimeout: 300 * time.Millisecond,
	}
	dnsHits      uint64
	dnsMisses    uint64
	dnsEvictions uint64
)

// resolveDomainTTL returns IPs and the TTL applied. It caches results until expiry.
// maxTTL bounds the cache duration; if zero, a default of 60s is used.
func resolveDomainTTL(domain string, maxTTL time.Duration) ([]net.IP, time.Duration) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return nil, 0
	}
	if maxTTL <= 0 {
		maxTTL = 60 * time.Second
	}
	now := time.Now()
	dnsMu.Lock()
	if ent, ok := dnsCache[d]; ok && now.Before(ent.expiry) {
		dnsHits++
		ttl := ent.expiry.Sub(now)
		dnsMu.Unlock()
		return ent.ips, ttl
	}
	dnsMisses++
	dnsMu.Unlock()

	nameserver := ""
	if conf, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(conf.Servers) > 0 {
		nameserver = net.JoinHostPort(conf.Servers[0], conf.Port)
	}
	useSystem := nameserver == ""

	// query A and AAAA
	var ips []net.IP
	minTTL := time.Duration(0)
	queries := []uint16{dns.TypeA, dns.TypeAAAA}
	for _, qt := range queries {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(d), qt)
		var resp *dns.Msg
		var err error
		if useSystem {
			// fallback to default resolver
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			addrs, derr := net.DefaultResolver.LookupIP(ctx, "ip", d)
			cancel()
			if derr == nil {
				for _, ip := range addrs {
					ips = append(ips, ip)
				}
				// TTL unknown; use maxTTL as hint
				minTTL = maxTTL
				continue
			}
		}
		resp, _, err = dnsClient.Exchange(msg, nameserver)
		if err != nil || resp == nil {
			continue
		}
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
				minTTL = updateTTL(minTTL, rr.Hdr.Ttl)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
				minTTL = updateTTL(minTTL, rr.Hdr.Ttl)
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0
	}
	if maxTTL <= 0 {
		maxTTL = 60 * time.Second
	}
	if minTTL <= 0 {
		minTTL = maxTTL
	} else {
		limit := minTTL
		if limit > maxTTL {
			limit = maxTTL
		}
		minTTL = limit
	}
	expiry := now.Add(minTTL)

	dnsMu.Lock()
	if len(dnsCache) >= dnsMaxEnt {
		// simple eviction: clear oldest entry
		var oldestKey string
		oldest := time.Now().Add(time.Hour)
		for k, v := range dnsCache {
			if v.expiry.Before(oldest) {
				oldest = v.expiry
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(dnsCache, oldestKey)
			dnsEvictions++
		}
	}
	dnsCache[d] = dnsEntry{ips: ips, expiry: expiry}
	dnsMu.Unlock()
	return ips, minTTL
}

// DNSCacheLen returns the current number of cached domains.
func DNSCacheLen() int {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return len(dnsCache)
}

// DNSMetrics returns counters since process start (best effort).
func DNSMetrics() map[string]uint64 {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return map[string]uint64{
		"hits":      dnsHits,
		"misses":    dnsMisses,
		"evictions": dnsEvictions,
	}
}

func updateTTL(current time.Duration, ttlSec uint32) time.Duration {
	d := time.Duration(ttlSec) * time.Second
	if current == 0 || d < current {
		return d
	}
	return current
}
