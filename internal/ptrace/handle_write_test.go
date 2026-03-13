//go:build linux

package ptrace

import "testing"

func TestSNIRewriteNeeded(t *testing.T) {
	ft := newFdTracker()
	ft.watchTLS(100, 5, "original.example.com")

	// fd not watched -> no rewrite
	if _, ok := ft.getTLSWatch(100, 99); ok {
		t.Fatal("unexpected TLS watch for unwatched fd")
	}

	// fd watched -> rewrite possible
	domain, ok := ft.getTLSWatch(100, 5)
	if !ok {
		t.Fatal("expected TLS watch")
	}
	if domain != "original.example.com" {
		t.Fatalf("expected domain 'original.example.com', got %q", domain)
	}
}
