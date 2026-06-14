package config

import "testing"

func TestResolveTorConfig_AbsentBlockDeniesByDefault(t *testing.T) {
	// Zero value = block omitted from YAML.
	got := ResolveTorConfig(TorConfig{})
	if !got.Enabled {
		t.Fatal("absent tor block must resolve to enabled (deny-by-default)")
	}
	if got.Mode != "deny" {
		t.Fatalf("Mode=%q, want deny", got.Mode)
	}
	for name, on := range map[string]bool{
		"processes": got.Vectors.Processes, "socks_ports": got.Vectors.SocksPorts,
		"onion_dns": got.Vectors.OnionDNS, "onion_http": got.Vectors.OnionHTTP,
		"relay_ips": got.Vectors.RelayIPs,
	} {
		if !on {
			t.Fatalf("vector %s must default on", name)
		}
	}
	if len(got.ClientBinaries) == 0 || len(got.SocksPorts) == 0 {
		t.Fatal("client_binaries and socks_ports must have defaults")
	}
}

func TestResolveTorConfig_ExplicitDisable(t *testing.T) {
	f := false
	got := ResolveTorConfig(TorConfig{Enabled: &f})
	if got.Enabled {
		t.Fatal("enabled:false must disable Tor controls")
	}
}

func TestResolveTorConfig_ExplicitAllowAndOverrides(t *testing.T) {
	tr := true
	got := ResolveTorConfig(TorConfig{
		Enabled:        &tr,
		Mode:           "allow",
		SocksPorts:     []int{9999},
		ClientBinaries: []string{"only-this"},
	})
	if got.Mode != "allow" {
		t.Fatalf("Mode=%q, want allow", got.Mode)
	}
	if len(got.SocksPorts) != 1 || got.SocksPorts[0] != 9999 {
		t.Fatalf("SocksPorts override not honored: %v", got.SocksPorts)
	}
	if len(got.ClientBinaries) != 1 || got.ClientBinaries[0] != "only-this" {
		t.Fatalf("ClientBinaries override not honored: %v", got.ClientBinaries)
	}
}

func TestResolveTorConfig_InvalidModeFallsBackToDeny(t *testing.T) {
	got := ResolveTorConfig(TorConfig{Mode: "banana"})
	if got.Mode != "deny" {
		t.Fatalf("invalid mode must fall back to deny, got %q", got.Mode)
	}
}
