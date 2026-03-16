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
	ft.recordDNSRedirect(100, 5, 100, "session1", "8.8.8.8:53")
	ft.closeFd(100, 5)

	if _, ok := ft.getTLSWatch(100, 5); ok {
		t.Fatal("TLS watch should be cleared after closeFd")
	}
	if ft.isStatusFd(100, 5) {
		t.Fatal("status fd should be cleared after closeFd")
	}
	if _, ok := ft.getDNSRedirect(100, 5); ok {
		t.Fatal("DNS redirect should be cleared after closeFd")
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

func TestFdTracker_NoWatchOnEmptyDomain(t *testing.T) {
	ft := newFdTracker()

	// domainForIP returns empty when IP has no DNS resolution recorded
	domain, ok := ft.domainForIP("192.168.1.1")
	if ok || domain != "" {
		t.Fatalf("expected no domain for unknown IP, got ok=%v domain=%q", ok, domain)
	}

	// Simulate the guard in handleConnectExit: only watch if domain is non-empty
	if ok && domain != "" {
		ft.watchTLS(100, 5, domain)
	}

	// Verify no TLS watch was armed
	if _, watched := ft.getTLSWatch(100, 5); watched {
		t.Fatal("TLS watch should not be armed for unknown domain")
	}
}

func TestFdTracker_GetLastDNSRedirect_Empty(t *testing.T) {
	ft := newFdTracker()
	_, ok := ft.getLastDNSRedirect()
	if ok {
		t.Fatal("expected no last redirect on fresh fdTracker")
	}
}

func TestFdTracker_GetLastDNSRedirect_Single(t *testing.T) {
	ft := newFdTracker()
	ft.recordDNSRedirect(100, 3, 100, "sess-1", "8.8.8.8:53")

	info, ok := ft.getLastDNSRedirect()
	if !ok {
		t.Fatal("expected last redirect to be set")
	}
	if info.pid != 100 {
		t.Fatalf("expected pid 100, got %d", info.pid)
	}
	if info.sessionID != "sess-1" {
		t.Fatalf("expected session sess-1, got %q", info.sessionID)
	}
	if info.originalResolver != "8.8.8.8:53" {
		t.Fatalf("expected resolver 8.8.8.8:53, got %q", info.originalResolver)
	}
}

func TestFdTracker_GetLastDNSRedirect_Overwrites(t *testing.T) {
	ft := newFdTracker()
	ft.recordDNSRedirect(100, 3, 100, "sess-1", "8.8.8.8:53")
	ft.recordDNSRedirect(200, 5, 200, "sess-2", "1.1.1.1:53")

	info, ok := ft.getLastDNSRedirect()
	if !ok {
		t.Fatal("expected last redirect to be set")
	}
	if info.sessionID != "sess-2" {
		t.Fatalf("expected latest session sess-2, got %q", info.sessionID)
	}
	if info.pid != 200 {
		t.Fatalf("expected pid 200, got %d", info.pid)
	}
}

func TestFdTracker_GetLastDNSRedirect_SurvivesPerKeyRemoval(t *testing.T) {
	ft := newFdTracker()
	ft.recordDNSRedirect(100, 3, 100, "sess-1", "8.8.8.8:53")
	ft.removeDNSRedirect(100, 3)

	// lastDNSRedirect should still be set even after per-key removal
	info, ok := ft.getLastDNSRedirect()
	if !ok {
		t.Fatal("expected last redirect to survive per-key removal")
	}
	if info.sessionID != "sess-1" {
		t.Fatalf("expected session sess-1, got %q", info.sessionID)
	}
}
