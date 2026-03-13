//go:build linux

package ptrace

import "sync"

// tgidFd is a composite key for per-TGID fd tracking.
type tgidFd struct {
	tgid int
	fd   int
}

// dnsRedirectInfo tracks the origin of a DNS connection redirected to the proxy.
type dnsRedirectInfo struct {
	pid              int
	sessionID        string
	originalResolver string // "ip:port" of the original DNS server
}

// fdTracker manages per-TGID fd tracking for TLS-watched fds,
// masked /proc/*/status fds, and DNS redirect source port mappings.
type fdTracker struct {
	mu sync.Mutex

	// TLS-watched fds: tgid+fd -> domain name (from DNS resolution)
	tlsWatched map[tgidFd]string

	// Masked /proc/*/status fds: tgid+fd -> tracked
	statusFds map[tgidFd]struct{}

	// DNS redirect: tgid+fd -> redirect info (for proxy PID lookup)
	dnsRedirects map[tgidFd]dnsRedirectInfo

	// IP -> domain mapping (populated by DNS proxy on resolution)
	ipToDomain map[string]string
}

func newFdTracker() *fdTracker {
	return &fdTracker{
		tlsWatched:   make(map[tgidFd]string),
		statusFds:    make(map[tgidFd]struct{}),
		dnsRedirects: make(map[tgidFd]dnsRedirectInfo),
		ipToDomain:   make(map[string]string),
	}
}

func (ft *fdTracker) watchTLS(tgid, fd int, domain string) {
	ft.mu.Lock()
	ft.tlsWatched[tgidFd{tgid, fd}] = domain
	ft.mu.Unlock()
}

func (ft *fdTracker) unwatchTLS(tgid, fd int) {
	ft.mu.Lock()
	delete(ft.tlsWatched, tgidFd{tgid, fd})
	ft.mu.Unlock()
}

func (ft *fdTracker) getTLSWatch(tgid, fd int) (domain string, ok bool) {
	ft.mu.Lock()
	domain, ok = ft.tlsWatched[tgidFd{tgid, fd}]
	ft.mu.Unlock()
	return
}

func (ft *fdTracker) trackStatusFd(tgid, fd int) {
	ft.mu.Lock()
	ft.statusFds[tgidFd{tgid, fd}] = struct{}{}
	ft.mu.Unlock()
}

func (ft *fdTracker) untrackStatusFd(tgid, fd int) {
	ft.mu.Lock()
	delete(ft.statusFds, tgidFd{tgid, fd})
	ft.mu.Unlock()
}

func (ft *fdTracker) isStatusFd(tgid, fd int) bool {
	ft.mu.Lock()
	_, ok := ft.statusFds[tgidFd{tgid, fd}]
	ft.mu.Unlock()
	return ok
}

func (ft *fdTracker) closeFd(tgid, fd int) {
	ft.mu.Lock()
	key := tgidFd{tgid, fd}
	delete(ft.tlsWatched, key)
	delete(ft.statusFds, key)
	delete(ft.dnsRedirects, key)
	ft.mu.Unlock()
}

func (ft *fdTracker) clearTGID(tgid int) {
	ft.mu.Lock()
	for k := range ft.tlsWatched {
		if k.tgid == tgid {
			delete(ft.tlsWatched, k)
		}
	}
	for k := range ft.statusFds {
		if k.tgid == tgid {
			delete(ft.statusFds, k)
		}
	}
	for k := range ft.dnsRedirects {
		if k.tgid == tgid {
			delete(ft.dnsRedirects, k)
		}
	}
	ft.mu.Unlock()
}

func (ft *fdTracker) recordDNSRedirect(tgid, fd, pid int, sessionID, originalResolver string) {
	ft.mu.Lock()
	ft.dnsRedirects[tgidFd{tgid, fd}] = dnsRedirectInfo{
		pid:              pid,
		sessionID:        sessionID,
		originalResolver: originalResolver,
	}
	ft.mu.Unlock()
}

func (ft *fdTracker) getDNSRedirect(tgid, fd int) (dnsRedirectInfo, bool) {
	ft.mu.Lock()
	info, ok := ft.dnsRedirects[tgidFd{tgid, fd}]
	ft.mu.Unlock()
	return info, ok
}

func (ft *fdTracker) removeDNSRedirect(tgid, fd int) {
	ft.mu.Lock()
	delete(ft.dnsRedirects, tgidFd{tgid, fd})
	ft.mu.Unlock()
}

func (ft *fdTracker) recordDNSResolution(ip, domain string) {
	ft.mu.Lock()
	ft.ipToDomain[ip] = domain
	ft.mu.Unlock()
}

func (ft *fdTracker) domainForIP(ip string) (string, bool) {
	ft.mu.Lock()
	domain, ok := ft.ipToDomain[ip]
	ft.mu.Unlock()
	return domain, ok
}
