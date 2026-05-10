package tlsleaf

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

const (
	leafValidFor = 90 * 24 * time.Hour
	leafCacheCap = 256
)

// IssueLeaf returns a tls.Certificate whose leaf is signed by the CA and
// whose only SAN is hostname. Cached in-process under hostname; cache size
// is bounded at 256 entries (LRU). Repeated calls for the same hostname
// return the cached certificate (no re-issuance).
func (c *CA) IssueLeaf(hostname string) (*tls.Certificate, error) {
	if hostname == "" {
		return nil, fmt.Errorf("tlsleaf: IssueLeaf: hostname is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = newLeafCache(leafCacheCap)
	}
	if cached, ok := c.cache.get(hostname); ok {
		return cached, nil
	}
	leaf, err := c.issueLeafLocked(hostname)
	if err != nil {
		return nil, err
	}
	c.cache.put(hostname, leaf)
	return leaf, nil
}

func (c *CA) issueLeafLocked(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	now := c.clk
	if now == nil {
		now = time.Now
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    t.Add(-1 * time.Hour),
		NotAfter:     t.Add(leafValidFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}, nil
}

// --- LRU cache (private; one instance per CA) ---

type leafCache struct {
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type leafEntry struct {
	host string
	leaf *tls.Certificate
}

func newLeafCache(cap int) *leafCache {
	return &leafCache{cap: cap, ll: list.New(), items: make(map[string]*list.Element, cap)}
}

func (c *leafCache) get(host string) (*tls.Certificate, bool) {
	el, ok := c.items[host]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*leafEntry).leaf, true
}

func (c *leafCache) put(host string, leaf *tls.Certificate) {
	if el, ok := c.items[host]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*leafEntry).leaf = leaf
		return
	}
	c.items[host] = c.ll.PushFront(&leafEntry{host: host, leaf: leaf})
	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*leafEntry).host)
		}
	}
}
