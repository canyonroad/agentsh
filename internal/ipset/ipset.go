// Package ipset provides membership testing for sets of individual IP
// addresses and CIDR ranges. A bare IP is stored as a /32 (IPv4) or
// /128 (IPv6) prefix. Safe for concurrent reads after construction;
// callers that mutate after publishing must provide their own locking
// or swap whole sets.
package ipset

import (
	"fmt"
	"net"
)

// Set holds IP/CIDR prefixes for O(n) membership testing. n is the
// number of distinct prefixes added (relay feeds: ~8k); linear scan is
// adequate and avoids a trie dependency. Swap whole sets to update.
type Set struct {
	nets []*net.IPNet
}

// New returns an empty Set.
func New() *Set { return &Set{} }

// Add inserts an IP ("1.2.3.4", "2001:db8::1") or CIDR ("10.0.0.0/8").
func (s *Set) Add(entry string) error {
	if _, ipnet, err := net.ParseCIDR(entry); err == nil {
		s.nets = append(s.nets, ipnet)
		return nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return fmt.Errorf("ipset: invalid entry %q", entry)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	mask := net.CIDRMask(bits, bits)
	s.nets = append(s.nets, &net.IPNet{IP: ip, Mask: mask})
	return nil
}

// Contains reports whether ip falls in any added prefix. nil → false.
func (s *Set) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Len returns the number of prefixes in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nets)
}
