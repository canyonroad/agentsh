package windows

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNATTable_InsertAndLookup(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	entry := &NATEntry{
		OriginalDstIP:   net.ParseIP("140.82.114.4"),
		OriginalDstPort: 443,
		Protocol:        "tcp",
		ProcessID:       1234,
		CreatedAt:       time.Now(),
	}

	table.Insert("127.0.0.1:54321", entry)

	got := table.Lookup("127.0.0.1:54321")
	if got == nil {
		t.Fatal("expected entry, got nil")
	}
	if !got.OriginalDstIP.Equal(entry.OriginalDstIP) {
		t.Errorf("OriginalDstIP = %v, want %v", got.OriginalDstIP, entry.OriginalDstIP)
	}
	if got.OriginalDstPort != 443 {
		t.Errorf("OriginalDstPort = %d, want 443", got.OriginalDstPort)
	}
}

func TestNATTable_LookupMissing(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	got := table.Lookup("127.0.0.1:99999")
	if got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
}

func TestNATTable_RemoveByPID(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	table.Insert("127.0.0.1:1001", &NATEntry{ProcessID: 100, OriginalDstPort: 80})
	table.Insert("127.0.0.1:1002", &NATEntry{ProcessID: 100, OriginalDstPort: 443})
	table.Insert("127.0.0.1:1003", &NATEntry{ProcessID: 200, OriginalDstPort: 80})

	removed := table.RemoveByPID(100)
	if removed != 2 {
		t.Errorf("RemoveByPID returned %d, want 2", removed)
	}

	if table.Lookup("127.0.0.1:1001") != nil {
		t.Error("entry for PID 100 should be removed")
	}
	if table.Lookup("127.0.0.1:1003") == nil {
		t.Error("entry for PID 200 should still exist")
	}
}

func TestNATTable_TTLExpiry(t *testing.T) {
	table := NewNATTable(50 * time.Millisecond)

	table.Insert("127.0.0.1:1001", &NATEntry{ProcessID: 100, OriginalDstPort: 80})

	// Should exist immediately
	if table.Lookup("127.0.0.1:1001") == nil {
		t.Fatal("entry should exist immediately after insert")
	}

	// Wait for TTL
	time.Sleep(100 * time.Millisecond)

	// Run cleanup
	table.Cleanup()

	// Should be gone
	if table.Lookup("127.0.0.1:1001") != nil {
		t.Error("entry should be expired after TTL")
	}
}

func TestNATTable_ConcurrentAccess(t *testing.T) {
	table := NewNATTable(5 * time.Minute)
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			table.Insert(fmt.Sprintf("127.0.0.1:%d", i), &NATEntry{ProcessID: uint32(i)})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			table.Lookup(fmt.Sprintf("127.0.0.1:%d", i))
		}
		done <- true
	}()

	<-done
	<-done
	// Test passes if no race detector errors
}

func TestNATEntry_IsRedirected(t *testing.T) {
	tests := []struct {
		name       string
		redirectTo string
		want       bool
	}{
		{"empty redirect", "", false},
		{"with redirect", "proxy.internal:443", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &NATEntry{
				OriginalDstIP:   net.ParseIP("10.0.0.1"),
				OriginalDstPort: 443,
				RedirectTo:      tt.redirectTo,
			}
			if got := entry.IsRedirected(); got != tt.want {
				t.Errorf("IsRedirected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNATEntry_GetConnectTarget(t *testing.T) {
	tests := []struct {
		name       string
		dstIP      string
		dstPort    uint16
		redirectTo string
		want       string
	}{
		{
			name:       "no redirect returns original",
			dstIP:      "10.0.0.1",
			dstPort:    443,
			redirectTo: "",
			want:       "10.0.0.1:443",
		},
		{
			name:       "with redirect returns redirect target",
			dstIP:      "10.0.0.1",
			dstPort:    443,
			redirectTo: "proxy.internal:443",
			want:       "proxy.internal:443",
		},
		{
			name:       "redirect with different port",
			dstIP:      "api.anthropic.com",
			dstPort:    443,
			redirectTo: "vertex-proxy.internal:8443",
			want:       "vertex-proxy.internal:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &NATEntry{
				OriginalDstIP:   net.ParseIP(tt.dstIP),
				OriginalDstPort: tt.dstPort,
				RedirectTo:      tt.redirectTo,
			}
			if got := entry.GetConnectTarget(); got != tt.want {
				t.Errorf("GetConnectTarget() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNATTable_InsertWithRedirect(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.0.1")

	// Test without redirect
	table.InsertWithRedirect("192.168.1.100:12345", dstIP, 443, "tcp", 1234, "", "", "")
	entry := table.Lookup("192.168.1.100:12345")
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if entry.IsRedirected() {
		t.Error("expected not redirected")
	}
	if got := entry.GetConnectTarget(); got != "10.0.0.1:443" {
		t.Errorf("GetConnectTarget() = %s, want 10.0.0.1:443", got)
	}

	// Test with redirect
	table.InsertWithRedirect("192.168.1.100:12346", dstIP, 443, "tcp", 1234,
		"proxy.internal:443", "rewrite_sni", "proxy.internal")
	entry = table.Lookup("192.168.1.100:12346")
	if entry == nil {
		t.Fatal("expected entry, got nil")
	}
	if !entry.IsRedirected() {
		t.Error("expected redirected")
	}
	if got := entry.GetConnectTarget(); got != "proxy.internal:443" {
		t.Errorf("GetConnectTarget() = %s, want proxy.internal:443", got)
	}
	if entry.RedirectTLS != "rewrite_sni" {
		t.Errorf("RedirectTLS = %s, want rewrite_sni", entry.RedirectTLS)
	}
	if entry.RedirectSNI != "proxy.internal" {
		t.Errorf("RedirectSNI = %s, want proxy.internal", entry.RedirectSNI)
	}

	// Verify original destination is preserved
	if !entry.OriginalDstIP.Equal(dstIP) {
		t.Errorf("OriginalDstIP = %v, want %v", entry.OriginalDstIP, dstIP)
	}
	if entry.OriginalDstPort != 443 {
		t.Errorf("OriginalDstPort = %d, want 443", entry.OriginalDstPort)
	}

	// Use srcIP to avoid unused variable warning
	_ = srcIP
}

func TestNATEntry_TLSPassthrough(t *testing.T) {
	// Test passthrough TLS mode (no SNI rewriting)
	entry := &NATEntry{
		OriginalDstIP:   net.ParseIP("93.184.216.34"),
		OriginalDstPort: 443,
		RedirectTo:      "proxy.internal:443",
		RedirectTLS:     "passthrough",
		RedirectSNI:     "", // Should be empty for passthrough
	}

	if !entry.IsRedirected() {
		t.Error("expected redirected")
	}
	if entry.RedirectTLS != "passthrough" {
		t.Errorf("RedirectTLS = %s, want passthrough", entry.RedirectTLS)
	}
	if entry.GetConnectTarget() != "proxy.internal:443" {
		t.Errorf("GetConnectTarget() = %s, want proxy.internal:443", entry.GetConnectTarget())
	}
}

func TestNATEntry_SNIRewrite(t *testing.T) {
	// Test rewrite_sni TLS mode with custom SNI
	entry := &NATEntry{
		OriginalDstIP:   net.ParseIP("140.82.114.4"),
		OriginalDstPort: 443,
		RedirectTo:      "vertex-proxy.corp:8443",
		RedirectTLS:     "rewrite_sni",
		RedirectSNI:     "vertex-proxy.corp",
	}

	if !entry.IsRedirected() {
		t.Error("expected redirected")
	}
	if entry.RedirectTLS != "rewrite_sni" {
		t.Errorf("RedirectTLS = %s, want rewrite_sni", entry.RedirectTLS)
	}
	if entry.RedirectSNI != "vertex-proxy.corp" {
		t.Errorf("RedirectSNI = %s, want vertex-proxy.corp", entry.RedirectSNI)
	}
	if entry.GetConnectTarget() != "vertex-proxy.corp:8443" {
		t.Errorf("GetConnectTarget() = %s, want vertex-proxy.corp:8443", entry.GetConnectTarget())
	}

	// Original destination should still be accessible
	if !entry.OriginalDstIP.Equal(net.ParseIP("140.82.114.4")) {
		t.Error("OriginalDstIP should be preserved")
	}
	if entry.OriginalDstPort != 443 {
		t.Error("OriginalDstPort should be preserved")
	}
}

func TestNATEntry_GetConnectTarget_IPv6(t *testing.T) {
	// Test with IPv6 address
	entry := &NATEntry{
		OriginalDstIP:   net.ParseIP("2607:f8b0:4004:800::200e"),
		OriginalDstPort: 443,
		RedirectTo:      "",
	}

	// Should format IPv6 correctly with brackets
	target := entry.GetConnectTarget()
	if target != "[2607:f8b0:4004:800::200e]:443" {
		t.Errorf("GetConnectTarget() = %s, want [2607:f8b0:4004:800::200e]:443", target)
	}
}

func TestNATTable_InsertWithRedirect_Overwrite(t *testing.T) {
	table := NewNATTable(5 * time.Minute)

	dstIP := net.ParseIP("10.0.0.1")

	// Insert without redirect
	table.InsertWithRedirect("127.0.0.1:5000", dstIP, 80, "tcp", 1234, "", "", "")
	entry := table.Lookup("127.0.0.1:5000")
	if entry.IsRedirected() {
		t.Error("expected not redirected initially")
	}

	// Overwrite with redirect
	table.InsertWithRedirect("127.0.0.1:5000", dstIP, 80, "tcp", 1234, "proxy:8080", "passthrough", "")
	entry = table.Lookup("127.0.0.1:5000")
	if !entry.IsRedirected() {
		t.Error("expected redirected after overwrite")
	}
	if entry.GetConnectTarget() != "proxy:8080" {
		t.Errorf("GetConnectTarget() = %s, want proxy:8080", entry.GetConnectTarget())
	}
}

func TestNATTable_InsertWithRedirect_Concurrent(t *testing.T) {
	table := NewNATTable(5 * time.Minute)
	done := make(chan bool)

	// Multiple writers with different redirect configs
	go func() {
		for i := 0; i < 500; i++ {
			key := fmt.Sprintf("127.0.0.1:%d", i)
			table.InsertWithRedirect(key, net.ParseIP("10.0.0.1"), 443, "tcp",
				uint32(i), "proxy:443", "passthrough", "")
		}
		done <- true
	}()

	go func() {
		for i := 500; i < 1000; i++ {
			key := fmt.Sprintf("127.0.0.1:%d", i)
			table.InsertWithRedirect(key, net.ParseIP("10.0.0.2"), 443, "tcp",
				uint32(i), "proxy:8443", "rewrite_sni", "proxy.internal")
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			key := fmt.Sprintf("127.0.0.1:%d", i%1000)
			entry := table.Lookup(key)
			if entry != nil {
				_ = entry.GetConnectTarget()
				_ = entry.IsRedirected()
			}
		}
		done <- true
	}()

	<-done
	<-done
	<-done
	// Test passes if no race detector errors
}

func TestNATEntry_OriginalDestinationPreserved(t *testing.T) {
	// Verify original destination is always preserved, even with redirect
	tests := []struct {
		name        string
		origIP      string
		origPort    uint16
		redirectTo  string
		redirectTLS string
		redirectSNI string
	}{
		{
			name:       "no redirect",
			origIP:     "93.184.216.34",
			origPort:   443,
			redirectTo: "",
		},
		{
			name:        "with passthrough redirect",
			origIP:      "140.82.114.4",
			origPort:    443,
			redirectTo:  "proxy:443",
			redirectTLS: "passthrough",
		},
		{
			name:        "with SNI rewrite redirect",
			origIP:      "142.250.189.206",
			origPort:    8443,
			redirectTo:  "vertex:443",
			redirectTLS: "rewrite_sni",
			redirectSNI: "vertex.corp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			table := NewNATTable(5 * time.Minute)
			origIP := net.ParseIP(tt.origIP)

			table.InsertWithRedirect("127.0.0.1:1234", origIP, tt.origPort, "tcp", 100,
				tt.redirectTo, tt.redirectTLS, tt.redirectSNI)

			entry := table.Lookup("127.0.0.1:1234")
			if entry == nil {
				t.Fatal("expected entry, got nil")
			}

			// Original destination should always be preserved
			if !entry.OriginalDstIP.Equal(origIP) {
				t.Errorf("OriginalDstIP = %v, want %v", entry.OriginalDstIP, origIP)
			}
			if entry.OriginalDstPort != tt.origPort {
				t.Errorf("OriginalDstPort = %d, want %d", entry.OriginalDstPort, tt.origPort)
			}
		})
	}
}
