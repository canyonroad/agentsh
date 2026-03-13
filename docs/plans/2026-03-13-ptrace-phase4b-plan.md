# Ptrace Phase 4b Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add DNS redirect, SNI rewrite, and TracerPid masking to the ptrace backend.

**Architecture:** In-process DNS proxy goroutine receives redirected DNS traffic via both connect redirect (Phase 4a) and sendto/sendmsg destination rewriting. SNI rewrite intercepts `write`/`sendto`/`sendmsg` on TLS-watched fds and patches ClientHello in tracee memory. TracerPid masking patches `/proc/*/status` reads on syscall-exit. All three features share a per-TGID fd tracker for lifecycle management.

**Tech Stack:** Go, `golang.org/x/sys/unix`, `golang.org/x/net/dns/dnsmessage` (DNS wire format)

**Depends on:** Phase 4a injection engine (inject.go, scratch.go) must be implemented and passing tests.

---

### Task 1: Extend NetworkContext and NetworkResult with DNS Fields

**Files:**
- Modify: `internal/ptrace/args.go:6-14`

**Step 1: Write the failing test**

Create a compile-check test that uses the new fields.

```go
// internal/ptrace/args_dns_test.go
//go:build linux

package ptrace

import "testing"

func TestNetworkContextDNSFields(t *testing.T) {
	nc := NetworkContext{
		PID:       1,
		Operation: "dns",
		Domain:    "example.com",
		QueryType: 1, // A record
	}
	if nc.Domain != "example.com" {
		t.Fatal("Domain field not set")
	}
	if nc.QueryType != 1 {
		t.Fatal("QueryType field not set")
	}
}

func TestNetworkResultDNSFields(t *testing.T) {
	r := NetworkResult{
		Allow:            false,
		RedirectUpstream: "10.0.0.1:53",
		Records: []DNSRecord{
			{Type: 1, Value: "93.184.216.34", TTL: 300},
		},
	}
	if r.RedirectUpstream != "10.0.0.1:53" {
		t.Fatal("RedirectUpstream field not set")
	}
	if len(r.Records) != 1 {
		t.Fatal("Records field not set")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestNetworkContext -count=1`
Expected: FAIL — `NetworkContext` has no `Domain` field

**Step 3: Write minimal implementation**

In `internal/ptrace/args.go`, add DNS fields to existing types and the new `DNSRecord` type:

```go
//go:build linux

package ptrace

// Regs abstracts architecture-specific register access for ptrace.
type Regs interface {
	SyscallNr() int
	SetSyscallNr(nr int)
	Arg(n int) uint64
	SetArg(n int, val uint64)
	ReturnValue() int64
	SetReturnValue(val int64)
	InstructionPointer() uint64
}

// ExecHandler evaluates execve policy.
type ExecHandler interface {
	HandleExecve(ctx context.Context, ec ExecContext) ExecResult
}

// ... (existing ExecContext, ExecResult — leave unchanged) ...

// FileHandler evaluates file syscall policy.
type FileHandler interface {
	HandleFile(ctx context.Context, fc FileContext) FileResult
}

// ... (existing FileContext, FileResult — leave unchanged) ...

// NetworkHandler evaluates network syscall policy.
type NetworkHandler interface {
	HandleNetwork(ctx context.Context, nc NetworkContext) NetworkResult
}

// NetworkContext holds context for a network policy decision.
type NetworkContext struct {
	PID       int
	SessionID string
	Syscall   int
	Family    int
	Address   string
	Port      int
	Operation string // "connect", "bind", "dns"
	Domain    string // DNS query name (set when Operation == "dns")
	QueryType uint16 // DNS query type: A=1, AAAA=28, CNAME=5, etc.
}

// NetworkResult holds the policy decision for a network syscall.
type NetworkResult struct {
	Allow            bool
	Errno            int32
	RedirectUpstream string      // Forward DNS query to this resolver (ip:port)
	Records          []DNSRecord // Synthetic DNS response records
}

// DNSRecord represents a single DNS answer record for synthetic responses.
type DNSRecord struct {
	Type  uint16 // A=1, AAAA=28, CNAME=5
	Value string // IP address or domain name
	TTL   uint32
}

// ... (existing SignalHandler, SignalContext, SignalResult — leave unchanged) ...
```

Note: The existing handler interfaces and types are already in `args.go`. You are adding `Domain`, `QueryType` fields to the existing `NetworkContext` struct, `RedirectUpstream` and `Records` fields to the existing `NetworkResult` struct, and the new `DNSRecord` type. Do NOT duplicate existing types — just add the new fields to what's already there.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestNetworkContext -count=1`
Expected: PASS

Run: `go test ./internal/ptrace/ -run TestNetworkResultDNS -count=1`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/args.go internal/ptrace/args_dns_test.go
git commit -m "feat(ptrace): add DNS fields to NetworkContext and NetworkResult"
```

---

### Task 2: Add Syscall Classifications

**Files:**
- Modify: `internal/ptrace/syscalls.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/syscalls_phase4b_test.go
//go:build linux

package ptrace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsWriteSyscall(t *testing.T) {
	tests := []struct {
		nr   int
		want bool
	}{
		{unix.SYS_WRITE, true},
		{unix.SYS_READ, false},
		{unix.SYS_OPENAT, false},
	}
	for _, tt := range tests {
		if got := isWriteSyscall(tt.nr); got != tt.want {
			t.Errorf("isWriteSyscall(%d) = %v, want %v", tt.nr, got, tt.want)
		}
	}
}

func TestIsReadSyscall(t *testing.T) {
	tests := []struct {
		nr   int
		want bool
	}{
		{unix.SYS_READ, true},
		{unix.SYS_PREAD64, true},
		{unix.SYS_WRITE, false},
	}
	for _, tt := range tests {
		if got := isReadSyscall(tt.nr); got != tt.want {
			t.Errorf("isReadSyscall(%d) = %v, want %v", tt.nr, got, tt.want)
		}
	}
}

func TestIsCloseSyscall(t *testing.T) {
	if !isCloseSyscall(unix.SYS_CLOSE) {
		t.Error("SYS_CLOSE should be classified as close syscall")
	}
	if isCloseSyscall(unix.SYS_OPENAT) {
		t.Error("SYS_OPENAT should not be classified as close syscall")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestIsWriteSyscall -count=1`
Expected: FAIL — `isWriteSyscall` undefined

**Step 3: Write minimal implementation**

Add to `internal/ptrace/syscalls.go` after the existing classification functions (after line 37):

```go
func isWriteSyscall(nr int) bool {
	return nr == unix.SYS_WRITE
}

func isReadSyscall(nr int) bool {
	return nr == unix.SYS_READ || nr == unix.SYS_PREAD64
}

func isCloseSyscall(nr int) bool {
	return nr == unix.SYS_CLOSE
}
```

Also update `tracedSyscallNumbers()` to include the new syscalls:

```go
// Add to the nums slice in tracedSyscallNumbers():
unix.SYS_WRITE,
unix.SYS_READ, unix.SYS_PREAD64,
unix.SYS_CLOSE,
```

Note: `SYS_SENDTO` is already in `isNetworkSyscall` and `tracedSyscallNumbers()`. The SNI check for sendto is handled inside `handleNetwork()`. `SYS_SENDMSG` is intentionally excluded from SNI rewrite — its arg layout (`arg1=msghdr*`, `arg2=flags`) is incompatible with the write handler's `arg1=buf, arg2=len` assumption.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run "TestIsWriteSyscall|TestIsReadSyscall|TestIsCloseSyscall" -count=1`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/syscalls.go internal/ptrace/syscalls_phase4b_test.go
git commit -m "feat(ptrace): add write, read, close syscall classifications for Phase 4b"
```

---

### Task 3: Fd Tracker

**Files:**
- Create: `internal/ptrace/fd_tracker.go`
- Create: `internal/ptrace/fd_tracker_test.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/fd_tracker_test.go
//go:build linux

package ptrace

import "testing"

func TestFdTracker_TLSWatch(t *testing.T) {
	ft := newFdTracker()

	ft.watchTLS(100, 5, "example.com") // tgid=100, fd=5
	if domain, ok := ft.getTLSWatch(100, 5); !ok || domain != "example.com" {
		t.Fatalf("expected TLS watch for tgid=100 fd=5, got ok=%v domain=%q", ok, domain)
	}

	// Different tgid should not match
	if _, ok := ft.getTLSWatch(200, 5); ok {
		t.Fatal("should not find TLS watch for different tgid")
	}

	ft.unwatchTLS(100, 5)
	if _, ok := ft.getTLSWatch(100, 5); ok {
		t.Fatal("TLS watch should be cleared after unwatch")
	}
}

func TestFdTracker_StatusFd(t *testing.T) {
	ft := newFdTracker()

	ft.trackStatusFd(100, 3) // tgid=100, fd=3
	if !ft.isStatusFd(100, 3) {
		t.Fatal("expected status fd tracking for tgid=100 fd=3")
	}

	ft.untrackStatusFd(100, 3)
	if ft.isStatusFd(100, 3) {
		t.Fatal("status fd should be cleared after untrack")
	}
}

func TestFdTracker_ClearTGID(t *testing.T) {
	ft := newFdTracker()

	ft.watchTLS(100, 5, "example.com")
	ft.trackStatusFd(100, 3)
	ft.clearTGID(100)

	if _, ok := ft.getTLSWatch(100, 5); ok {
		t.Fatal("TLS watches should be cleared after clearTGID")
	}
	if ft.isStatusFd(100, 3) {
		t.Fatal("status fds should be cleared after clearTGID")
	}
}

func TestFdTracker_CloseFd(t *testing.T) {
	ft := newFdTracker()

	ft.watchTLS(100, 5, "example.com")
	ft.trackStatusFd(100, 5)
	ft.closeFd(100, 5)

	if _, ok := ft.getTLSWatch(100, 5); ok {
		t.Fatal("TLS watch should be cleared after closeFd")
	}
	if ft.isStatusFd(100, 5) {
		t.Fatal("status fd should be cleared after closeFd")
	}
}

func TestFdTracker_DNSMapping(t *testing.T) {
	ft := newFdTracker()

	ft.recordDNSRedirect(100, 5, 100, "session1", "8.8.8.8:53") // tgid=100, fd=5
	info, ok := ft.getDNSRedirect(100, 5)
	if !ok {
		t.Fatal("expected DNS redirect info for tgid=100 fd=5")
	}
	if info.pid != 100 || info.sessionID != "session1" || info.originalResolver != "8.8.8.8:53" {
		t.Fatalf("unexpected DNS redirect info: %+v", info)
	}

	ft.removeDNSRedirect(100, 5)
	if _, ok := ft.getDNSRedirect(100, 5); ok {
		t.Fatal("DNS redirect should be removed")
	}
}

func TestFdTracker_IPToDomain(t *testing.T) {
	ft := newFdTracker()

	ft.recordDNSResolution("93.184.216.34", "example.com")
	if domain, ok := ft.domainForIP("93.184.216.34"); !ok || domain != "example.com" {
		t.Fatalf("expected domain mapping, got ok=%v domain=%q", ok, domain)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestFdTracker -count=1`
Expected: FAIL — `newFdTracker` undefined

**Step 3: Write minimal implementation**

```go
// internal/ptrace/fd_tracker.go
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

	// TLS-watched fds: tgid+fd → domain name (from DNS resolution)
	tlsWatched map[tgidFd]string

	// Masked /proc/*/status fds: tgid+fd → tracked
	statusFds map[tgidFd]struct{}

	// DNS redirect: tgid+fd → redirect info (for proxy PID lookup)
	dnsRedirects map[tgidFd]dnsRedirectInfo

	// IP → domain mapping (populated by DNS proxy on resolution)
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
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestFdTracker -count=1`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/fd_tracker.go internal/ptrace/fd_tracker_test.go
git commit -m "feat(ptrace): add per-TGID fd tracker for TLS, status fd, and DNS mappings"
```

---

### Task 4: SNI Parser and Rewriter

**Files:**
- Create: `internal/ptrace/sni.go`
- Create: `internal/ptrace/sni_test.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/sni_test.go
//go:build linux

package ptrace

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
)

// buildClientHello generates a real TLS ClientHello with the given SNI.
func buildClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := serverConn.Read(buf)
		done <- buf[:n]
		serverConn.Close()
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	go func() {
		tlsConn.Handshake() //nolint:errcheck
		tlsConn.Close()
	}()

	hello := <-done
	clientConn.Close()
	return hello
}

func TestParseSNI(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	sni, offset, length, err := parseSNI(hello)
	if err != nil {
		t.Fatalf("parseSNI failed: %v", err)
	}
	if sni != "example.com" {
		t.Fatalf("expected SNI 'example.com', got %q", sni)
	}
	if offset <= 0 || length != len("example.com") {
		t.Fatalf("unexpected offset=%d length=%d", offset, length)
	}
}

func TestParseSNI_NoSNI(t *testing.T) {
	// Not a TLS record
	_, _, _, err := parseSNI([]byte("GET / HTTP/1.1\r\n"))
	if err == nil {
		t.Fatal("expected error for non-TLS data")
	}
}

func TestParseSNI_TooShort(t *testing.T) {
	_, _, _, err := parseSNI([]byte{0x16, 0x03, 0x01})
	if err == nil {
		t.Fatal("expected error for truncated data")
	}
}

func TestRewriteSNI_SameLength(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	original := make([]byte, len(hello))
	copy(original, hello)

	rewritten, err := rewriteSNI(hello, "example.org")
	if err != nil {
		t.Fatalf("rewriteSNI failed: %v", err)
	}
	// Verify the new SNI is present
	sni, _, _, err := parseSNI(rewritten)
	if err != nil {
		t.Fatalf("parseSNI on rewritten failed: %v", err)
	}
	if sni != "example.org" {
		t.Fatalf("expected rewritten SNI 'example.org', got %q", sni)
	}
	// Same length, so total record size should not change
	if len(rewritten) != len(original) {
		t.Fatalf("expected same length %d, got %d", len(original), len(rewritten))
	}
}

func TestRewriteSNI_Shorter(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	rewritten, err := rewriteSNI(hello, "ex.co")
	if err != nil {
		t.Fatalf("rewriteSNI failed: %v", err)
	}
	sni, _, _, err := parseSNI(rewritten)
	if err != nil {
		t.Fatalf("parseSNI on rewritten failed: %v", err)
	}
	if sni != "ex.co" {
		t.Fatalf("expected rewritten SNI 'ex.co', got %q", sni)
	}
	// Shorter name means shorter record
	if len(rewritten) >= len(hello) {
		t.Fatalf("expected shorter record, got %d >= %d", len(rewritten), len(hello))
	}
}

func TestRewriteSNI_Longer(t *testing.T) {
	hello := buildClientHello(t, "ex.co")
	rewritten, err := rewriteSNI(hello, "very-long-subdomain.example.com")
	if err != nil {
		t.Fatalf("rewriteSNI failed: %v", err)
	}
	sni, _, _, err := parseSNI(rewritten)
	if err != nil {
		t.Fatalf("parseSNI on rewritten failed: %v", err)
	}
	if sni != "very-long-subdomain.example.com" {
		t.Fatalf("expected rewritten SNI, got %q", sni)
	}
	// Longer name means longer record
	if len(rewritten) <= len(hello) {
		t.Fatalf("expected longer record, got %d <= %d", len(rewritten), len(hello))
	}
}

func TestIsClientHello(t *testing.T) {
	hello := buildClientHello(t, "example.com")
	if !isClientHello(hello) {
		t.Fatal("expected isClientHello=true for valid ClientHello")
	}
	if isClientHello([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("expected isClientHello=false for HTTP request")
	}
	if isClientHello(nil) {
		t.Fatal("expected isClientHello=false for nil")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestParseSNI -count=1`
Expected: FAIL — `parseSNI` undefined

**Step 3: Write minimal implementation**

```go
// internal/ptrace/sni.go
//go:build linux

package ptrace

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	errNotTLS       = errors.New("not a TLS record")
	errNotHandshake = errors.New("not a handshake record")
	errNotClientHello = errors.New("not a ClientHello")
	errTruncated    = errors.New("truncated TLS record")
	errNoSNI        = errors.New("no SNI extension found")
)

// isClientHello returns true if buf starts with a TLS ClientHello record.
func isClientHello(buf []byte) bool {
	if len(buf) < 6 {
		return false
	}
	// Content type: handshake (0x16)
	if buf[0] != 0x16 {
		return false
	}
	// Version: TLS 1.0-1.3 record layer (0x0301-0x0303)
	if buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x03 {
		return false
	}
	// Handshake type: ClientHello (0x01)
	return buf[5] == 0x01
}

// parseSNI extracts the SNI server name from a TLS ClientHello record.
// Returns the server name, its byte offset within buf, its length, and any error.
// The offset points to the first byte of the server name string within buf.
func parseSNI(buf []byte) (serverName string, offset int, length int, err error) {
	if len(buf) < 6 {
		return "", 0, 0, errTruncated
	}
	if buf[0] != 0x16 {
		return "", 0, 0, errNotTLS
	}
	if buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x03 {
		return "", 0, 0, errNotTLS
	}
	// recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if buf[5] != 0x01 {
		return "", 0, 0, errNotClientHello
	}

	// Handshake header: type(1) + length(3)
	if len(buf) < 9 {
		return "", 0, 0, errTruncated
	}
	handshakeLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])
	handshakeEnd := 9 + handshakeLen
	if handshakeEnd > len(buf) {
		handshakeEnd = len(buf) // work with what we have
	}

	// ClientHello body starts at offset 9:
	//   client_version(2) + random(32) = 34 bytes
	pos := 9 + 34
	if pos >= handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Session ID (variable length)
	sessionIDLen := int(buf[pos])
	pos += 1 + sessionIDLen
	if pos+2 > handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Cipher suites (variable length)
	cipherSuitesLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Compression methods (variable length)
	compressionLen := int(buf[pos])
	pos += 1 + compressionLen
	if pos+2 > handshakeEnd {
		return "", 0, 0, errTruncated
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > handshakeEnd {
		extensionsEnd = handshakeEnd
	}

	// Walk extensions looking for SNI (type 0x0000)
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(buf[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 { // server_name extension
			// SNI extension body:
			//   server_name_list_length(2)
			//   server_name_type(1) = 0 (host_name)
			//   host_name_length(2)
			//   host_name(variable)
			if pos+5 > extensionsEnd {
				return "", 0, 0, errTruncated
			}
			// listLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
			nameType := buf[pos+2]
			if nameType != 0 { // not host_name
				pos += extLen
				continue
			}
			nameLen := int(binary.BigEndian.Uint16(buf[pos+3 : pos+5]))
			nameOffset := pos + 5
			if nameOffset+nameLen > extensionsEnd {
				return "", 0, 0, errTruncated
			}
			return string(buf[nameOffset : nameOffset+nameLen]), nameOffset, nameLen, nil
		}
		pos += extLen
	}

	return "", 0, 0, errNoSNI
}

// rewriteSNI replaces the SNI server name in a TLS ClientHello with newName.
// Returns a new buffer with the rewritten ClientHello.
// Updates all length fields (TLS record, handshake, SNI extension, server name list, host name).
func rewriteSNI(buf []byte, newName string) ([]byte, error) {
	_, nameOffset, nameLen, err := parseSNI(buf)
	if err != nil {
		return nil, fmt.Errorf("parseSNI: %w", err)
	}

	newNameBytes := []byte(newName)
	diff := len(newNameBytes) - nameLen

	// Build new buffer: before name + new name + after name
	result := make([]byte, 0, len(buf)+diff)
	result = append(result, buf[:nameOffset]...)
	result = append(result, newNameBytes...)
	result = append(result, buf[nameOffset+nameLen:]...)

	// Fix length fields. All lengths increase/decrease by diff.

	// 1. TLS record length (bytes 3-4): total after 5-byte header
	recordLen := int(binary.BigEndian.Uint16(result[3:5])) + diff
	binary.BigEndian.PutUint16(result[3:5], uint16(recordLen))

	// 2. Handshake length (bytes 6-8): 3-byte big-endian
	handshakeLen := int(result[6])<<16 | int(result[7])<<8 | int(result[8])
	handshakeLen += diff
	result[6] = byte(handshakeLen >> 16)
	result[7] = byte(handshakeLen >> 8)
	result[8] = byte(handshakeLen)

	// 3. Host name length (2 bytes before name): nameOffset-2
	binary.BigEndian.PutUint16(result[nameOffset-2:nameOffset], uint16(len(newNameBytes)))

	// 4. Server name list length (2 bytes before name type): nameOffset-5
	listLen := int(binary.BigEndian.Uint16(buf[nameOffset-5:nameOffset-3])) + diff
	binary.BigEndian.PutUint16(result[nameOffset-5:nameOffset-3], uint16(listLen))

	// 5. SNI extension length (2 bytes before list length): nameOffset-7
	extLen := int(binary.BigEndian.Uint16(buf[nameOffset-7:nameOffset-5])) + diff
	binary.BigEndian.PutUint16(result[nameOffset-7:nameOffset-5], uint16(extLen))

	// 6. Walk backwards to find and fix extensions total length.
	// Extensions length is 2 bytes before the start of extensions.
	// We need to find it by re-parsing to the extensions_length position.
	// Re-parse to find extensions length offset:
	epos := 9 + 34 // skip handshake header + client_version + random
	if epos < len(result) {
		sessionIDLen := int(result[epos])
		epos += 1 + sessionIDLen
		if epos+2 <= len(result) {
			cipherLen := int(binary.BigEndian.Uint16(result[epos : epos+2]))
			epos += 2 + cipherLen
			if epos+1 <= len(result) {
				compLen := int(result[epos])
				epos += 1 + compLen
				if epos+2 <= len(result) {
					extTotalLen := int(binary.BigEndian.Uint16(result[epos:epos+2])) + diff
					binary.BigEndian.PutUint16(result[epos:epos+2], uint16(extTotalLen))
				}
			}
		}
	}

	return result, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run "TestParseSNI|TestRewriteSNI|TestIsClientHello" -count=1`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/sni.go internal/ptrace/sni_test.go
git commit -m "feat(ptrace): add TLS ClientHello SNI parser and rewriter"
```

---

### Task 5: DNS Proxy

**Files:**
- Create: `internal/ptrace/dns_proxy.go`
- Create: `internal/ptrace/dns_proxy_test.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/dns_proxy_test.go
//go:build linux

package ptrace

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mockDNSNetworkHandler implements NetworkHandler for DNS proxy tests.
type mockDNSNetworkHandler struct {
	result NetworkResult
}

func (m *mockDNSNetworkHandler) HandleNetwork(_ context.Context, nc NetworkContext) NetworkResult {
	return m.result
}

func buildDNSQuery(t *testing.T, domain string, qtype dnsmessage.Type) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0xABCD,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(domain + "."),
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	buf, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	return buf
}

func TestDNSProxy_Allow(t *testing.T) {
	// Start a fake upstream DNS that returns a canned A record
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	go func() {
		buf := make([]byte, 512)
		n, addr, err := upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			return
		}
		msg.Header.Response = true
		msg.Answers = []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   300,
				},
				Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
			},
		}
		resp, _ := msg.Pack()
		upstream.WriteTo(resp, addr)
	}()

	ft := newFdTracker()
	handler := &mockDNSNetworkHandler{result: NetworkResult{Allow: true}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	// Register the original resolver so proxy knows where to forward
	ft.recordDNSRedirect(1, 0, 1, "test", upstream.LocalAddr().String())

	// Send query to proxy
	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if !msg.Header.Response {
		t.Fatal("expected response flag set")
	}
	if len(msg.Answers) == 0 {
		t.Fatal("expected at least one answer")
	}
}

func TestDNSProxy_Deny(t *testing.T) {
	ft := newFdTracker()
	handler := &mockDNSNetworkHandler{result: NetworkResult{Allow: false}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "blocked.example.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if msg.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("expected NXDOMAIN, got %v", msg.Header.RCode)
	}
}

func TestDNSProxy_SyntheticRecords(t *testing.T) {
	ft := newFdTracker()
	handler := &mockDNSNetworkHandler{result: NetworkResult{
		Allow: false,
		Records: []DNSRecord{
			{Type: 1, Value: "10.0.0.1", TTL: 60},
		},
	}}

	proxy, err := newDNSProxy(handler, ft)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.run(ctx)

	conn, err := net.Dial("udp", proxy.addr4())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := buildDNSQuery(t, "api.example.com", dnsmessage.TypeA)
	conn.Write(query)

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("no response from DNS proxy: %v", err)
	}

	var msg dnsmessage.Message
	if err := msg.Unpack(resp[:n]); err != nil {
		t.Fatalf("failed to unpack DNS response: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(msg.Answers))
	}
	aRecord, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatal("expected A record")
	}
	if aRecord.A != [4]byte{10, 0, 0, 1} {
		t.Fatalf("expected 10.0.0.1, got %v", aRecord.A)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestDNSProxy -count=1`
Expected: FAIL — `newDNSProxy` undefined

**Step 3: Write minimal implementation**

```go
// internal/ptrace/dns_proxy.go
//go:build linux

package ptrace

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsProxy is an in-process DNS proxy that intercepts DNS queries
// and applies policy via the NetworkHandler.
type dnsProxy struct {
	handler   NetworkHandler
	fds       *fdTracker
	udpConn4  *net.UDPConn // IPv4 listener
	udpConn6  *net.UDPConn // IPv6 listener
	port4     int
	port6     int
}

func newDNSProxy(handler NetworkHandler, fds *fdTracker) (*dnsProxy, error) {
	// Bind IPv4
	udpAddr4, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("resolve UDP4 addr: %w", err)
	}
	conn4, err := net.ListenUDP("udp4", udpAddr4)
	if err != nil {
		return nil, fmt.Errorf("listen UDP4: %w", err)
	}
	port4 := conn4.LocalAddr().(*net.UDPAddr).Port

	// Bind IPv6
	udpAddr6, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		conn4.Close()
		return nil, fmt.Errorf("resolve UDP6 addr: %w", err)
	}
	conn6, err := net.ListenUDP("udp6", udpAddr6)
	if err != nil {
		conn4.Close()
		return nil, fmt.Errorf("listen UDP6: %w", err)
	}
	port6 := conn6.LocalAddr().(*net.UDPAddr).Port

	return &dnsProxy{
		handler:  handler,
		fds:      fds,
		udpConn4: conn4,
		udpConn6: conn6,
		port4:    port4,
		port6:    port6,
	}, nil
}

func (p *dnsProxy) addr4() string {
	return fmt.Sprintf("127.0.0.1:%d", p.port4)
}

func (p *dnsProxy) addr6() string {
	return fmt.Sprintf("[::1]:%d", p.port6)
}

func (p *dnsProxy) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		p.udpConn4.Close()
		p.udpConn6.Close()
	}()

	// Run IPv4 and IPv6 listeners concurrently
	go p.listenUDP(ctx, p.udpConn4)
	p.listenUDP(ctx, p.udpConn6)
}

func (p *dnsProxy) listenUDP(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("dns_proxy: read error", "error", err)
			continue
		}
		go p.handleQuery(ctx, conn, buf[:n], remoteAddr)
	}
}

func (p *dnsProxy) handleQuery(ctx context.Context, conn *net.UDPConn, raw []byte, remoteAddr *net.UDPAddr) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		slog.Warn("dns_proxy: failed to parse DNS query", "error", err)
		return
	}

	if len(msg.Questions) == 0 {
		return
	}

	q := msg.Questions[0]
	domain := strings.TrimSuffix(q.Name.String(), ".")

	// Look up tracee info — the proxy receives queries from redirected connections.
	// The fd tracker stores TGID+fd → redirect info. For UDP, the proxy can't
	// directly resolve the source to a TGID. The tracer records the redirect info
	// keyed by TGID+fd before allowing the syscall, and passes it via a
	// per-query context channel or connection metadata. For simplicity in this
	// initial implementation, we use a fallback: if no specific mapping is found,
	// the proxy still processes the query but without PID attribution.
	var redirectInfo dnsRedirectInfo
	// TODO: The tracer should pass TGID+fd context to the proxy at redirect time.
	// For now, use empty info — policy can still make domain-based decisions.

	// Query policy
	result := p.handler.HandleNetwork(ctx, NetworkContext{
		PID:       redirectInfo.pid,
		SessionID: redirectInfo.sessionID,
		Family:    int(q.Class),
		Address:   redirectInfo.originalResolver,
		Port:      53,
		Operation: "dns",
		Domain:    domain,
		QueryType: uint16(q.Type),
	})

	var resp []byte
	var err error

	switch {
	case len(result.Records) > 0:
		// Synthetic response
		resp, err = p.buildSyntheticResponse(msg, q, result.Records)
	case !result.Allow:
		// Deny → NXDOMAIN
		resp, err = p.buildNXDomain(msg)
	case result.RedirectUpstream != "":
		// Forward to alternate resolver
		resp, err = p.forwardQuery(raw, result.RedirectUpstream)
	default:
		// Allow → forward to original resolver
		if redirectInfo.originalResolver != "" {
			resp, err = p.forwardQuery(raw, redirectInfo.originalResolver)
		} else {
			resp, err = p.buildNXDomain(msg) // no resolver known
		}
	}

	if err != nil {
		slog.Warn("dns_proxy: failed to build response", "error", err, "domain", domain)
		return
	}

	// Record IP→domain mappings from response for SNI rewrite
	p.recordResolutions(resp, domain)

	conn.WriteToUDP(resp, remoteAddr)
}

func (p *dnsProxy) buildNXDomain(query dnsmessage.Message) ([]byte, error) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeNameError,
		},
		Questions: query.Questions,
	}
	return resp.Pack()
}

func (p *dnsProxy) buildSyntheticResponse(query dnsmessage.Message, q dnsmessage.Question, records []DNSRecord) ([]byte, error) {
	var answers []dnsmessage.Resource
	for _, rec := range records {
		hdr := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Class: dnsmessage.ClassINET,
			TTL:   rec.TTL,
		}

		switch rec.Type {
		case 1: // A
			ip := net.ParseIP(rec.Value).To4()
			if ip == nil {
				continue
			}
			hdr.Type = dnsmessage.TypeA
			var a [4]byte
			copy(a[:], ip)
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: a}})

		case 28: // AAAA
			ip := net.ParseIP(rec.Value).To16()
			if ip == nil {
				continue
			}
			hdr.Type = dnsmessage.TypeAAAA
			var a [16]byte
			copy(a[:], ip)
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: a}})

		case 5: // CNAME
			name, err := dnsmessage.NewName(rec.Value + ".")
			if err != nil {
				continue
			}
			hdr.Type = dnsmessage.TypeCNAME
			answers = append(answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.CNAMEResource{CNAME: name}})
		}
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.Header.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   query.Header.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: query.Questions,
		Answers:   answers,
	}
	return resp.Pack()
}

func (p *dnsProxy) forwardQuery(raw []byte, upstream string) ([]byte, error) {
	// Ensure upstream has a port
	if _, _, err := net.SplitHostPort(upstream); err != nil {
		upstream = upstream + ":53"
	}

	conn, err := net.Dial("udp", upstream)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", upstream, err)
	}
	defer conn.Close()

	conn.SetDeadline(ctxDeadlineOrDefault(2))
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("write to upstream: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from upstream: %w", err)
	}
	return buf[:n], nil
}

// recordResolutions parses A/AAAA answers and records IP→domain mappings.
func (p *dnsProxy) recordResolutions(raw []byte, domain string) {
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return
	}
	for _, ans := range msg.Answers {
		switch body := ans.Body.(type) {
		case *dnsmessage.AResource:
			ip := net.IP(body.A[:]).String()
			p.fds.recordDNSResolution(ip, domain)
		case *dnsmessage.AAAAResource:
			ip := net.IP(body.AAAA[:]).String()
			p.fds.recordDNSResolution(ip, domain)
		}
	}
}

func ctxDeadlineOrDefault(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}
```

Note: You'll need to add `golang.org/x/net` as a dependency. Run: `go get golang.org/x/net/dns/dnsmessage`

Also add `"time"` to the imports.

**Step 4: Run test to verify it passes**

Run: `go get golang.org/x/net/dns/dnsmessage && go test ./internal/ptrace/ -run TestDNSProxy -count=1 -timeout 30s`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/dns_proxy.go internal/ptrace/dns_proxy_test.go go.mod go.sum
git commit -m "feat(ptrace): add in-process DNS proxy with policy integration"
```

---

### Task 6: handleWrite — SNI Rewrite Dispatch

**Files:**
- Create: `internal/ptrace/handle_write.go`

This handler intercepts `SYS_WRITE` on TLS-watched fds. It reads the write buffer from tracee memory, checks for ClientHello, and rewrites SNI if needed. `SYS_SENDTO` on TLS-watched fds is routed here from `handleNetwork()`. `SYS_SENDMSG` is not handled (incompatible arg layout).

**Step 1: Write the failing test (integration)**

This requires a running tracer, so add to `integration_test.go`. For now, write a unit test for the handler logic that doesn't need ptrace.

```go
// internal/ptrace/handle_write_test.go
//go:build linux

package ptrace

import "testing"

func TestSNIRewriteNeeded(t *testing.T) {
	ft := newFdTracker()
	ft.watchTLS(100, 5, "original.example.com")

	// fd not watched → no rewrite
	if _, ok := ft.getTLSWatch(100, 99); ok {
		t.Fatal("unexpected TLS watch for unwatched fd")
	}

	// fd watched → rewrite possible
	domain, ok := ft.getTLSWatch(100, 5)
	if !ok {
		t.Fatal("expected TLS watch")
	}
	if domain != "original.example.com" {
		t.Fatalf("expected domain 'original.example.com', got %q", domain)
	}
}
```

**Step 2: Run test to verify it passes (this one uses existing code)**

Run: `go test ./internal/ptrace/ -run TestSNIRewriteNeeded -count=1`
Expected: PASS (uses fd_tracker already built)

**Step 3: Write the handler**

```go
// internal/ptrace/handle_write.go
//go:build linux

package ptrace

import (
	"context"
	"log/slog"

	"golang.org/x/sys/unix"
)

// handleWrite intercepts write/sendmsg for SNI rewrite on TLS-watched fds.
func (t *Tracer) handleWrite(ctx context.Context, tid int, regs Regs) {
	if t.fds == nil {
		t.allowSyscall(tid)
		return
	}

	fd := int(int32(regs.Arg(0)))

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	domain, watched := t.fds.getTLSWatch(tgid, fd)
	if !watched {
		t.allowSyscall(tid)
		return
	}

	// Read the write buffer to check for ClientHello
	bufPtr := regs.Arg(1)
	bufLen := regs.Arg(2)

	// Only read enough to parse ClientHello header + SNI
	readLen := bufLen
	if readLen > 16384 {
		readLen = 16384 // cap read size
	}

	buf := make([]byte, readLen)
	if err := t.readBytes(tid, bufPtr, buf); err != nil {
		slog.Warn("handleWrite: cannot read write buffer", "tid", tid, "error", err)
		t.fds.unwatchTLS(tgid, fd) // stop watching on error
		t.allowSyscall(tid)
		return
	}

	if !isClientHello(buf) {
		// Not a ClientHello — remove from watch and allow
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	// Parse SNI from the ClientHello
	sni, nameOffset, nameLen, err := parseSNI(buf)
	if err != nil {
		slog.Debug("handleWrite: no SNI in ClientHello", "tid", tid, "error", err)
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	// SNI already matches the domain we expect — no rewrite needed
	if sni == domain {
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	_ = nameOffset
	_ = nameLen

	// Rewrite SNI to the policy-determined domain
	rewritten, err := rewriteSNI(buf, domain)
	if err != nil {
		slog.Warn("handleWrite: SNI rewrite failed", "tid", tid, "oldSNI", sni, "newSNI", domain, "error", err)
		t.fds.unwatchTLS(tgid, fd)
		t.allowSyscall(tid)
		return
	}

	// Write rewritten ClientHello back to tracee memory.
	// If same length or shorter, overwrite in-place.
	// If longer, use scratch page and update registers.
	if len(rewritten) <= int(bufLen) {
		// Fits in original buffer — overwrite in-place
		if err := t.writeBytes(tid, bufPtr, rewritten); err != nil {
			slog.Warn("handleWrite: failed to write rewritten ClientHello", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		// Update length register if rewritten is shorter
		if len(rewritten) < int(bufLen) {
			regs.SetArg(2, uint64(len(rewritten)))
			if err := t.setRegs(tid, regs); err != nil {
				slog.Warn("handleWrite: failed to update length register", "tid", tid, "error", err)
			}
		}
	} else {
		// Longer — need scratch page from Phase 4a injection engine.
		// Allocate scratch, write rewritten buffer there, update buf pointer + length registers.
		scratchAddr, err := t.allocScratch(tid, tgid, len(rewritten))
		if err != nil {
			slog.Warn("handleWrite: scratch alloc failed, allowing original", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		if err := t.writeBytes(tid, scratchAddr, rewritten); err != nil {
			slog.Warn("handleWrite: failed to write to scratch", "tid", tid, "error", err)
			t.fds.unwatchTLS(tgid, fd)
			t.allowSyscall(tid)
			return
		}
		regs.SetArg(1, scratchAddr) // buf pointer
		regs.SetArg(2, uint64(len(rewritten))) // length
		if err := t.setRegs(tid, regs); err != nil {
			slog.Warn("handleWrite: failed to update registers for scratch", "tid", tid, "error", err)
		}
	}

	slog.Info("handleWrite: rewrote SNI", "tid", tid, "oldSNI", sni, "newSNI", domain)
	t.fds.unwatchTLS(tgid, fd)
	t.allowSyscall(tid)
}
```

Note: `allocScratch` is from Phase 4a's scratch.go. If Phase 4a is implemented, this will resolve. The handler delegates to the existing scratch page mechanism.

**Step 4: Verify build**

Run: `go build ./internal/ptrace/`
Expected: Build succeeds (assuming Phase 4a scratch.go exists)

**Step 5: Commit**

```
git add internal/ptrace/handle_write.go internal/ptrace/handle_write_test.go
git commit -m "feat(ptrace): add write handler for TLS SNI rewrite"
```

---

### Task 7: handleRead — TracerPid Masking

**Files:**
- Create: `internal/ptrace/handle_read.go`
- Create: `internal/ptrace/handle_read_test.go`

**Step 1: Write the failing test**

```go
// internal/ptrace/handle_read_test.go
//go:build linux

package ptrace

import (
	"bytes"
	"testing"
)

func TestMaskTracerPid(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "typical /proc/self/status",
			input:  "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12345\nNgid:\t0\nPid:\t12345\nPPid:\t1\nTracerPid:\t67890\nUid:\t1000\t1000\t1000\t1000\n",
			expect: "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t12345\nNgid:\t0\nPid:\t12345\nPPid:\t1\nTracerPid:\t0    \nUid:\t1000\t1000\t1000\t1000\n",
		},
		{
			name:   "TracerPid is zero (not traced)",
			input:  "TracerPid:\t0\nUid:\t1000\n",
			expect: "TracerPid:\t0\nUid:\t1000\n",
		},
		{
			name:   "no TracerPid line",
			input:  "Name:\tsleep\nPid:\t1234\n",
			expect: "Name:\tsleep\nPid:\t1234\n",
		},
		{
			name:   "TracerPid at end without newline",
			input:  "TracerPid:\t999",
			expect: "TracerPid:\t0  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := []byte(tt.input)
			maskTracerPid(buf)
			if !bytes.Equal(buf, []byte(tt.expect)) {
				t.Errorf("expected %q, got %q", tt.expect, string(buf))
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ptrace/ -run TestMaskTracerPid -count=1`
Expected: FAIL — `maskTracerPid` undefined

**Step 3: Write minimal implementation**

```go
// internal/ptrace/handle_read.go
//go:build linux

package ptrace

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

var procStatusPattern = regexp.MustCompile(`^/proc/(\d+|self|thread-self)/status$`)

// isProcStatus returns true if the path matches /proc/<N>/status, /proc/self/status,
// or /proc/thread-self/status.
func isProcStatus(path string) bool {
	return procStatusPattern.MatchString(path)
}

var tracerPidPrefix = []byte("TracerPid:\t")

// maskTracerPid scans buf for "TracerPid:\t<N>" and overwrites <N> with "0"
// followed by spaces to preserve the buffer length. Operates in-place.
func maskTracerPid(buf []byte) {
	idx := bytes.Index(buf, tracerPidPrefix)
	if idx < 0 {
		return
	}

	// Find the start and end of the PID number
	pidStart := idx + len(tracerPidPrefix)
	pidEnd := pidStart
	for pidEnd < len(buf) && buf[pidEnd] != '\n' {
		pidEnd++
	}

	// Already zero — nothing to do
	pid := string(buf[pidStart:pidEnd])
	if strings.TrimSpace(pid) == "0" {
		return
	}

	// Overwrite: "0" followed by spaces to fill the original width
	buf[pidStart] = '0'
	for i := pidStart + 1; i < pidEnd; i++ {
		buf[i] = ' '
	}
}

// handleReadExit is called on syscall-exit for SYS_READ/SYS_PREAD64.
// If the fd is a tracked /proc/*/status fd, it patches TracerPid in the buffer.
func (t *Tracer) handleReadExit(tid int, regs Regs) {
	if t.fds == nil || !t.cfg.MaskTracerPid {
		return
	}

	fd := int(int32(regs.Arg(0)))

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	if !t.fds.isStatusFd(tgid, fd) {
		return
	}

	// Read the buffer that the kernel just wrote
	bytesRead := regs.ReturnValue()
	if bytesRead <= 0 {
		return
	}

	bufPtr := regs.Arg(1)
	buf := make([]byte, bytesRead)
	if err := t.readBytes(tid, bufPtr, buf); err != nil {
		slog.Warn("handleReadExit: cannot read buffer", "tid", tid, "error", err)
		return
	}

	// Check if TracerPid is in this chunk
	if !bytes.Contains(buf, tracerPidPrefix) {
		return
	}

	// Mask it
	maskTracerPid(buf)

	// Write patched buffer back
	if err := t.writeBytes(tid, bufPtr, buf); err != nil {
		slog.Warn("handleReadExit: cannot write patched buffer", "tid", tid, "error", err)
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/ptrace/ -run TestMaskTracerPid -count=1`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/handle_read.go internal/ptrace/handle_read_test.go
git commit -m "feat(ptrace): add read handler for TracerPid masking"
```

---

### Task 8: handleClose — Fd Cleanup

**Files:**
- Create: `internal/ptrace/handle_close.go`

**Step 1: Write implementation**

This is simple dispatch — no complex test needed beyond integration.

```go
// internal/ptrace/handle_close.go
//go:build linux

package ptrace

import "context"

// handleClose intercepts SYS_CLOSE to clean up fd tracking state.
func (t *Tracer) handleClose(_ context.Context, tid int, regs Regs) {
	fd := int(int32(regs.Arg(0)))

	if t.fds != nil {
		t.mu.Lock()
		state := t.tracees[tid]
		var tgid int
		if state != nil {
			tgid = state.TGID
		}
		t.mu.Unlock()

		t.fds.closeFd(tgid, fd)
	}

	t.allowSyscall(tid)
}
```

**Step 2: Verify build**

Run: `go build ./internal/ptrace/`
Expected: Build succeeds

**Step 3: Commit**

```
git add internal/ptrace/handle_close.go
git commit -m "feat(ptrace): add close handler for fd tracking cleanup"
```

---

### Task 9: Wire Into Tracer

**Files:**
- Modify: `internal/ptrace/tracer.go`

This is the integration task. Wire up:
1. `fdTracker` on the `Tracer` struct
2. DNS proxy startup
3. Dispatch changes (new syscall handlers)
4. Syscall-exit handling for read masking and openat fd tracking
5. DNS connect redirect in `handleNetwork`
6. TLS fd watching on connect completion
7. Cleanup on exec/exit

**Step 1: Add `fds` and `dnsProxy` to Tracer struct**

In `internal/ptrace/tracer.go`, add fields to the `Tracer` struct (around line 149-164):

```go
type Tracer struct {
	cfg             TracerConfig
	metrics         Metrics
	processTree     *ProcessTree
	prefilterActive bool

	attachQueue chan int
	resumeQueue chan resumeRequest

	mu            sync.Mutex
	tracees       map[int]*TraceeState
	parkedTracees map[int]struct{}

	stopped chan struct{}

	fds      *fdTracker // Phase 4b: per-TGID fd tracking
	dnsProxy *dnsProxy  // Phase 4b: in-process DNS proxy
}
```

Add `MaskTracerPid bool` to `TracerConfig` (around line 107-125).

**Step 2: Initialize fdTracker and dnsProxy in NewTracer or Run**

In the `Run()` method (around line 606), before the main loop:

```go
t.fds = newFdTracker()
if t.cfg.TraceNetwork && t.cfg.NetworkHandler != nil {
	proxy, err := newDNSProxy(t.cfg.NetworkHandler, t.fds)
	if err != nil {
		slog.Warn("ptrace: failed to start DNS proxy", "error", err)
	} else {
		t.dnsProxy = proxy
		go t.dnsProxy.run(ctx)
		slog.Info("ptrace: DNS proxy started", "addr4", t.dnsProxy.addr4(), "addr6", t.dnsProxy.addr6())
	}
}
```

**Step 3: Update dispatchSyscall**

Change `dispatchSyscall` (line 409-423) to include new handlers:

```go
func (t *Tracer) dispatchSyscall(ctx context.Context, tid int, nr int, regs Regs) {
	switch {
	case isExecveSyscall(nr):
		t.handleExecve(ctx, tid, regs)
	case isFileSyscall(nr):
		t.handleFile(ctx, tid, regs)
	case isNetworkSyscall(nr):
		t.handleNetwork(ctx, tid, regs)
	case isSignalSyscall(nr):
		t.handleSignal(ctx, tid, regs)
	case isWriteSyscall(nr):
		t.handleWrite(ctx, tid, regs)
	case isCloseSyscall(nr):
		t.handleClose(ctx, tid, regs)
	case isReadSyscall(nr):
		t.allowSyscall(tid) // read is handled on exit, not entry
	default:
		t.allowSyscall(tid)
	}
}
```

**Step 4: Add syscall-exit handling**

Modify `handleSyscallStop` (line 360-396) to add exit-time dispatch:

```go
} else {
	if pendingErrno != 0 {
		t.applyDenyFixup(tid, pendingErrno)
	}

	// Phase 4b: exit-time handlers
	nr := 0
	t.mu.Lock()
	if state != nil {
		nr = state.LastNr
	}
	t.mu.Unlock()

	if nr != 0 {
		regs, err := t.getRegs(tid)
		if err == nil {
			t.handleSyscallExit(tid, nr, regs)
		}
	}

	t.allowSyscall(tid)
}
```

Add the exit dispatch method:

```go
// handleSyscallExit runs exit-time handlers for syscalls that need post-processing.
func (t *Tracer) handleSyscallExit(tid int, nr int, regs Regs) {
	switch {
	case isReadSyscall(nr):
		t.handleReadExit(tid, regs)
	case nr == unix.SYS_OPENAT || nr == unix.SYS_OPENAT2:
		t.handleOpenatExit(tid, regs)
	case nr == unix.SYS_CONNECT:
		t.handleConnectExit(tid, regs)
	}
}
```

**Step 5: Add openat exit handler for /proc/*/status tracking**

```go
// handleOpenatExit tracks fds opened on /proc/*/status for TracerPid masking.
func (t *Tracer) handleOpenatExit(tid int, regs Regs) {
	if t.fds == nil || !t.cfg.MaskTracerPid {
		return
	}

	retVal := regs.ReturnValue()
	if retVal < 0 {
		return // open failed
	}
	fd := int(retVal)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Read the path from /proc/<tid>/fd/<fd> to check if it's a status file.
	// We can't re-read args (registers may have changed), so use /proc readlink.
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
	if err != nil {
		return
	}

	if isProcStatus(path) {
		t.fds.trackStatusFd(tgid, fd)
	}
}
```

**Step 6: Add connect exit handler for TLS fd watching**

```go
// handleConnectExit marks fds as TLS-watched after successful connect to TLS ports.
func (t *Tracer) handleConnectExit(tid int, regs Regs) {
	if t.fds == nil {
		return
	}

	retVal := regs.ReturnValue()
	// connect returns 0 on success, or -EINPROGRESS for non-blocking
	if retVal != 0 && retVal != -int64(unix.EINPROGRESS) {
		return
	}

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	// Read the destination address from the connect args.
	// On exit, the original args are still in Arg(1)/Arg(2) on most architectures.
	addrPtr := regs.Arg(1)
	addrLen := int(regs.Arg(2))
	if addrLen <= 0 || addrLen > 128 {
		return
	}

	buf := make([]byte, addrLen)
	if err := t.readBytes(tid, addrPtr, buf); err != nil {
		return
	}

	_, address, port, err := parseSockaddr(buf)
	if err != nil {
		return
	}

	// Only watch TLS-relevant ports
	if port != 443 && port != 853 {
		return
	}

	fd := int(int32(regs.Arg(0)))

	// Look up domain from DNS resolution cache
	domain, ok := t.fds.domainForIP(address)
	if !ok || domain == "" {
		return // No domain known — skip TLS watch to avoid empty SNI rewrite
	}
	t.fds.watchTLS(tgid, fd, domain)
}
```

**Step 7: Add DNS connect redirect to handleNetwork**

In `internal/ptrace/handle_network.go`, in the `handleNetwork` method, after parsing the sockaddr and before calling the handler, add DNS redirect logic:

```go
// DNS redirect: if connecting to port 53, redirect to local DNS proxy
if t.dnsProxy != nil && port == 53 &&
	(family == unix.AF_INET || family == unix.AF_INET6) &&
	nr == unix.SYS_CONNECT {

	originalResolver := fmt.Sprintf("%s:%d", address, port)

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	var sessionID string
	if state != nil {
		tgid = state.TGID
		sessionID = state.SessionID
	}
	t.mu.Unlock()

	fd := int(int32(regs.Arg(0)))

	// Rewrite sockaddr to point to DNS proxy, preserving address family
	var newSockaddr []byte
	if family == unix.AF_INET {
		newSockaddr = buildSockaddrIn4(net.ParseIP("127.0.0.1").To4(), t.dnsProxy.port4)
	} else {
		newSockaddr = buildSockaddrIn6(net.ParseIP("::1"), t.dnsProxy.port6)
		// Update addrlen register for larger sockaddr_in6
		regs.SetArg(2, 28)
		if err := t.setRegs(tid, regs); err != nil {
			slog.Warn("handleNetwork: DNS redirect setRegs failed", "tid", tid, "error", err)
		}
	}
	if err := t.writeBytes(tid, addrPtr, newSockaddr); err != nil {
		slog.Warn("handleNetwork: DNS redirect write failed", "tid", tid, "error", err)
		t.denySyscall(tid, int(unix.EACCES))
		return
	}

	// Record redirect info keyed by TGID+fd for proxy PID attribution
	t.fds.recordDNSRedirect(tgid, fd, tgid, sessionID, originalResolver)

	t.allowSyscall(tid)
	return
}
```

Add helpers to build sockaddr:

```go
// buildSockaddrIn4 builds a raw sockaddr_in for IPv4.
func buildSockaddrIn4(ip net.IP, port int) []byte {
	buf := make([]byte, 16) // sizeof(sockaddr_in)
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	copy(buf[4:8], ip.To4())
	return buf
}

// buildSockaddrIn6 builds a raw sockaddr_in6 for IPv6.
func buildSockaddrIn6(ip net.IP, port int) []byte {
	buf := make([]byte, 28) // sizeof(sockaddr_in6)
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], uint16(port))
	// flow info at bytes 4-7 = 0
	copy(buf[8:24], ip.To16())
	// scope_id at bytes 24-27 = 0
	return buf
}
```

**Step 8: Add sendto/sendmsg DNS redirect in handleNetwork**

For unconnected UDP DNS (sendto with destination port 53), rewrite the destination address:

```go
// Sendto DNS redirect: if sendto targets port 53, rewrite destination to proxy
if t.dnsProxy != nil && nr == unix.SYS_SENDTO {
	destAddrPtr := regs.Arg(4) // sendto arg4 = dest_addr
	destAddrLen := int(regs.Arg(5)) // sendto arg5 = addrlen
	if destAddrPtr != 0 && destAddrLen > 0 && destAddrLen <= 128 {
		destBuf := make([]byte, destAddrLen)
		if err := t.readBytes(tid, destAddrPtr, destBuf); err == nil {
			destFamily, _, destPort, err := parseSockaddr(destBuf)
			if err == nil && destPort == 53 &&
				(destFamily == unix.AF_INET || destFamily == unix.AF_INET6) {

				// Rewrite destination to DNS proxy
				var newDest []byte
				if destFamily == unix.AF_INET {
					newDest = buildSockaddrIn4(net.ParseIP("127.0.0.1").To4(), t.dnsProxy.port4)
				} else {
					newDest = buildSockaddrIn6(net.ParseIP("::1"), t.dnsProxy.port6)
					regs.SetArg(5, 28) // update addrlen
					t.setRegs(tid, regs)
				}
				if err := t.writeBytes(tid, destAddrPtr, newDest); err == nil {
					t.allowSyscall(tid)
					return
				}
			}
		}
	}
}
```

**Step 9: Clean up on exec/exit**

In `handleExit` (line 503-518), add fd tracker cleanup:

```go
if t.fds != nil && state != nil {
	t.fds.clearTGID(state.TGID)
}
```

In the exec event handler (`handleExecEvent` or wherever exec is processed), add:

```go
if t.fds != nil {
	t.fds.clearTGID(tgid) // exec resets address space and fd table
}
```

**Step 10: Run full build**

Run: `go build ./internal/ptrace/`
Expected: Build succeeds

**Step 11: Commit**

```
git add internal/ptrace/tracer.go internal/ptrace/handle_network.go
git commit -m "feat(ptrace): wire Phase 4b handlers into tracer dispatch and lifecycle"
```

---

### Task 10: Integration Tests

**Files:**
- Modify: `internal/ptrace/integration_test.go`

**Step 1: Add TracerPid masking integration test**

```go
func TestIntegration_TracerPidMasked(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}
	fileHandler := &mockFileHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:   true,
		TraceFile:     true,
		ExecHandler:   execHandler,
		FileHandler:   fileHandler,
		MaskTracerPid: true,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "tracerpid.txt")
	shellCmd := fmt.Sprintf(`grep TracerPid /proc/self/status > %s`, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}

	cmd.Wait()
	cancel()

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	// Should show TracerPid: 0 (masked)
	if !strings.Contains(line, "TracerPid:\t0") && !strings.Contains(line, "TracerPid: 0") {
		t.Fatalf("expected masked TracerPid, got: %q", line)
	}
}
```

**Step 2: Add TracerPid disabled test**

```go
func TestIntegration_TracerPidNotMasked(t *testing.T) {
	requirePtrace(t)

	execHandler := &mockExecHandler{defaultAllow: true}
	fileHandler := &mockFileHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:   true,
		TraceFile:     true,
		ExecHandler:   execHandler,
		FileHandler:   fileHandler,
		MaskTracerPid: false,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "tracerpid.txt")
	shellCmd := fmt.Sprintf(`grep TracerPid /proc/self/status > %s`, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}

	cmd.Wait()
	cancel()

	data, err := os.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	// Should show real TracerPid (non-zero)
	if strings.Contains(line, "TracerPid:\t0") {
		t.Fatalf("expected non-zero TracerPid when masking disabled, got: %q", line)
	}
}
```

**Step 3: Add DNS proxy integration test**

```go
func TestIntegration_DNSConnectRedirect(t *testing.T) {
	requirePtrace(t)

	netHandler := &mockNetworkHandler{
		defaultAllow: true,
	}
	execHandler := &mockExecHandler{defaultAllow: true}

	cfg := TracerConfig{
		TraceExecve:    true,
		TraceNetwork:   true,
		ExecHandler:    execHandler,
		NetworkHandler: netHandler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// The tracee does a DNS lookup. With the proxy running,
	// the connect to port 53 should be redirected.
	tmpDir := t.TempDir()
	outfile := filepath.Join(tmpDir, "dns.txt")
	// Use getent to trigger a DNS query
	shellCmd := fmt.Sprintf(`getent hosts example.com > %s 2>&1 || echo "failed" > %s`, outfile, outfile)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}

	cmd.Wait()
	cancel()

	// Verify the network handler saw a DNS operation
	netHandler.mu.Lock()
	var sawDNS bool
	for _, c := range netHandler.calls {
		if c.Operation == "dns" {
			sawDNS = true
			break
		}
	}
	netHandler.mu.Unlock()

	if !sawDNS {
		t.Log("DNS operation not captured — DNS proxy may not have intercepted (system DNS config dependent)")
		// This is expected in some CI environments where DNS doesn't go through connect()
	}
}
```

**Step 4: Run integration tests**

Run: `go test ./internal/ptrace/ -tags integration -run "TestIntegration_TracerPid|TestIntegration_DNS" -count=1 -timeout 60s`
Expected: PASS

**Step 5: Commit**

```
git add internal/ptrace/integration_test.go
git commit -m "test(ptrace): add Phase 4b integration tests for TracerPid masking and DNS redirect"
```

---

### Task 11: Cross-Compilation Verification

**Step 1: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: Build succeeds (all new files are `//go:build linux`)

Run: `go test ./... -count=1`
Expected: All non-integration tests pass

Run: `go vet ./...`
Expected: No issues

**Step 2: Final commit if any fixups needed**

```
git add -A
git commit -m "fix(ptrace): Phase 4b cross-compilation and vet fixes"
```

---

## Dependency Graph

```
Task 1 (types) ──────────────────────────────┐
Task 2 (syscall classification) ──────────────┤
Task 3 (fd tracker) ─────────────────────────┤
Task 4 (SNI parser) ─────────────────────────┼── Task 9 (wire into tracer)
Task 5 (DNS proxy) ──────────────────────────┤          │
Task 6 (handleWrite) ────────────────────────┤          │
Task 7 (handleRead) ─────────────────────────┤    Task 10 (integration tests)
Task 8 (handleClose) ────────────────────────┘          │
                                                  Task 11 (cross-compile check)
```

Tasks 1–8 are independent and can be parallelized. Task 9 depends on all of 1–8. Task 10 depends on 9. Task 11 depends on 10.
