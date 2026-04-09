package capabilities

import (
	"testing"
)

func TestValidateStrictMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		caps    SecurityCapabilities
		wantErr bool
	}{
		{
			name: "full mode with all caps",
			mode: ModeFull,
			caps: SecurityCapabilities{
				Seccomp: true, EBPF: true, FUSE: true,
			},
			wantErr: false,
		},
		{
			name: "full mode missing seccomp",
			mode: ModeFull,
			caps: SecurityCapabilities{
				Seccomp: false, EBPF: true, FUSE: true,
			},
			wantErr: true,
		},
		{
			name: "full mode missing eBPF",
			mode: ModeFull,
			caps: SecurityCapabilities{
				Seccomp: true, EBPF: false, FUSE: true,
			},
			wantErr: true,
		},
		{
			name: "full mode missing FUSE",
			mode: ModeFull,
			caps: SecurityCapabilities{
				Seccomp: true, EBPF: true, FUSE: false,
			},
			wantErr: true,
		},
		{
			name: "landlock mode with Landlock + FUSE",
			mode: ModeLandlock,
			caps: SecurityCapabilities{
				Landlock: true, FUSE: true,
			},
			wantErr: false,
		},
		{
			name: "landlock mode missing FUSE",
			mode: ModeLandlock,
			caps: SecurityCapabilities{
				Landlock: true, FUSE: false,
			},
			wantErr: true,
		},
		{
			name: "landlock mode missing Landlock",
			mode: ModeLandlock,
			caps: SecurityCapabilities{
				Landlock: false, FUSE: true,
			},
			wantErr: true,
		},
		{
			name: "landlock-only mode with Landlock",
			mode: ModeLandlockOnly,
			caps: SecurityCapabilities{
				Landlock: true,
			},
			wantErr: false,
		},
		{
			name: "landlock-only mode missing Landlock",
			mode: ModeLandlockOnly,
			caps: SecurityCapabilities{
				Landlock: false,
			},
			wantErr: true,
		},
		{
			name: "minimal always passes",
			mode: ModeMinimal,
			caps: SecurityCapabilities{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStrictMode(tt.mode, &tt.caps)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStrictMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMinimumMode(t *testing.T) {
	tests := []struct {
		name     string
		selected string
		minimum  string
		wantErr  bool
	}{
		{
			name:     "full meets full minimum",
			selected: ModeFull,
			minimum:  ModeFull,
			wantErr:  false,
		},
		{
			name:     "full meets landlock minimum",
			selected: ModeFull,
			minimum:  ModeLandlock,
			wantErr:  false,
		},
		{
			name:     "landlock meets landlock minimum",
			selected: ModeLandlock,
			minimum:  ModeLandlock,
			wantErr:  false,
		},
		{
			name:     "landlock fails full minimum",
			selected: ModeLandlock,
			minimum:  ModeFull,
			wantErr:  true,
		},
		{
			name:     "minimal fails landlock minimum",
			selected: ModeMinimal,
			minimum:  ModeLandlock,
			wantErr:  true,
		},
		{
			name:     "landlock-only fails landlock minimum",
			selected: ModeLandlockOnly,
			minimum:  ModeLandlock,
			wantErr:  true,
		},
		{
			name:     "landlock-only meets landlock-only minimum",
			selected: ModeLandlockOnly,
			minimum:  ModeLandlockOnly,
			wantErr:  false,
		},
		{
			name:     "empty minimum always passes",
			selected: ModeMinimal,
			minimum:  "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMinimumMode(tt.selected, tt.minimum)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMinimumMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePolicyForMode(t *testing.T) {
	// Test that warnings are generated for rules that can't be enforced
	caps := &SecurityCapabilities{
		Seccomp:         false,
		LandlockNetwork: false,
		EBPF:            false,
	}

	warnings := ValidatePolicyForMode(caps, true, true, true)

	// Should have warnings for unix sockets, signals, and network
	if len(warnings) != 3 {
		t.Errorf("expected 3 warnings, got %d", len(warnings))
	}

	// Verify warning types
	hasUnixWarning := false
	hasSignalWarning := false
	hasNetworkWarning := false

	for _, w := range warnings {
		if contains(w.Message, "Unix socket") {
			hasUnixWarning = true
		}
		if contains(w.Message, "Signal") {
			hasSignalWarning = true
		}
		if contains(w.Message, "Network") {
			hasNetworkWarning = true
		}
	}

	if !hasUnixWarning {
		t.Error("expected warning about Unix sockets")
	}
	if !hasSignalWarning {
		t.Error("expected warning about signals")
	}
	if !hasNetworkWarning {
		t.Error("expected warning about network")
	}
}

func TestValidatePolicyForMode_NoWarnings(t *testing.T) {
	caps := &SecurityCapabilities{
		Seccomp:         true,
		LandlockNetwork: true,
		EBPF:            true,
	}

	warnings := ValidatePolicyForMode(caps, true, true, true)

	if len(warnings) != 0 {
		t.Errorf("expected no warnings when all caps available, got %d", len(warnings))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestModeDescriptionWithCaps covers the minimal-mode honesty fix from
// the branch-level roborev review on #198. Before the split, a root
// process running in minimal mode always got the log/startup string
// "capability dropping only (~50% policy enforcement)" even when the
// behavioural probe reported no caps had been dropped. The resulting
// startup line was internally contradictory (description claimed
// dropping was active; capabilities_active=false contradicted it).
//
// ModeDescriptionWithCaps now gates the "capability dropping only"
// wording on CapabilitiesActive so the no-drop root case gets an
// honest "no active enforcement primitives" description instead.
// Other modes are unchanged regardless of the caps handle (fast path
// back to ModeDescription).
func TestModeDescriptionWithCaps(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		caps     *SecurityCapabilities
		wantSub  string
		denySub  string // substring that must NOT appear
	}{
		{
			name:    "minimal with active capability drop",
			mode:    ModeMinimal,
			caps:    &SecurityCapabilities{CapabilitiesActive: true},
			wantSub: "capability dropping only",
		},
		{
			name:    "minimal with no capability drop (root/full caps)",
			mode:    ModeMinimal,
			caps:    &SecurityCapabilities{CapabilitiesActive: false},
			wantSub: "no active enforcement primitives",
			denySub: "capability dropping only",
		},
		{
			name:    "minimal with nil caps falls back to generic wording",
			mode:    ModeMinimal,
			caps:    nil,
			wantSub: "fallback mode",
			denySub: "capability dropping only",
		},
		{
			name:    "full mode ignores caps",
			mode:    ModeFull,
			caps:    &SecurityCapabilities{CapabilitiesActive: false},
			wantSub: "Full security",
		},
		{
			name:    "landlock mode ignores caps",
			mode:    ModeLandlock,
			caps:    &SecurityCapabilities{CapabilitiesActive: false},
			wantSub: "Landlock security",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ModeDescriptionWithCaps(tt.mode, tt.caps)
			if !contains(got, tt.wantSub) {
				t.Errorf("ModeDescriptionWithCaps(%q, %+v) = %q; want substring %q",
					tt.mode, tt.caps, got, tt.wantSub)
			}
			if tt.denySub != "" && contains(got, tt.denySub) {
				t.Errorf("ModeDescriptionWithCaps(%q, %+v) = %q; must NOT contain %q",
					tt.mode, tt.caps, got, tt.denySub)
			}
		})
	}
}
