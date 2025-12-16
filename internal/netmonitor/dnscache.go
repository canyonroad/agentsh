package netmonitor

import (
	"net"
	"sync"
	"time"
)

type DNSCache struct {
	maxAge time.Duration

	mu   sync.Mutex
	byIP map[string]dnsEntry
}

type dnsEntry struct {
	domain    string
	expiresAt time.Time
}

func NewDNSCache(maxAge time.Duration) *DNSCache {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	return &DNSCache{
		maxAge: maxAge,
		byIP:   make(map[string]dnsEntry),
	}
}

func (c *DNSCache) Record(domain string, ips []net.IP, now time.Time) {
	if c == nil || domain == "" || len(ips) == 0 {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	exp := now.Add(c.maxAge)

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if key == "" {
			continue
		}
		c.byIP[key] = dnsEntry{domain: domain, expiresAt: exp}
	}
}

func (c *DNSCache) LookupByIP(ip net.IP, now time.Time) (string, bool) {
	if c == nil || ip == nil {
		return "", false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	key := ip.String()
	if key == "" {
		return "", false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.byIP[key]
	if !ok {
		return "", false
	}
	if now.After(ent.expiresAt) {
		delete(c.byIP, key)
		return "", false
	}
	return ent.domain, true
}

func parseDNSAnswerIPs(msg []byte) []net.IP {
	if len(msg) < 12 {
		return nil
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])

	i := 12
	for q := 0; q < qd; q++ {
		var ok bool
		i, ok = skipDNSName(msg, i)
		if !ok || i+4 > len(msg) {
			return nil
		}
		i += 4 // qtype + qclass
	}

	var out []net.IP
	for a := 0; a < an; a++ {
		var ok bool
		i, ok = skipDNSName(msg, i)
		if !ok || i+10 > len(msg) {
			return out
		}
		typ := int(msg[i])<<8 | int(msg[i+1])
		// class := int(msg[i+2])<<8 | int(msg[i+3])
		rdlen := int(msg[i+8])<<8 | int(msg[i+9])
		i += 10
		if i+rdlen > len(msg) {
			return out
		}

		switch typ {
		case 1: // A
			if rdlen == 4 {
				out = append(out, net.IPv4(msg[i], msg[i+1], msg[i+2], msg[i+3]))
			}
		case 28: // AAAA
			if rdlen == 16 {
				ip := make([]byte, 16)
				copy(ip, msg[i:i+16])
				out = append(out, net.IP(ip))
			}
		}
		i += rdlen
	}
	return out
}

func skipDNSName(msg []byte, i int) (int, bool) {
	for {
		if i >= len(msg) {
			return 0, false
		}
		l := msg[i]
		if l == 0 {
			return i + 1, true
		}
		if l&0xC0 == 0xC0 {
			if i+1 >= len(msg) {
				return 0, false
			}
			return i + 2, true
		}
		if l&0xC0 != 0 {
			return 0, false
		}
		i++
		i += int(l)
	}
}
