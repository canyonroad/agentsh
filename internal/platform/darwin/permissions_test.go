//go:build darwin

package darwin

import (
	"strings"
	"testing"
)

func TestPermissionTier_String(t *testing.T) {
	tests := []struct {
		tier PermissionTier
		want string
	}{
		{TierEnterprise, "enterprise"},
		{TierStandard, "standard"},
		{TierMinimal, "minimal"},
		{PermissionTier(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.tier.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPermissionTier_SecurityScore(t *testing.T) {
	tests := []struct {
		tier PermissionTier
		want int
	}{
		{TierEnterprise, 95},
		{TierStandard, 50},
		{TierMinimal, 10},
		{PermissionTier(99), 0},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			if got := tt.tier.SecurityScore(); got != tt.want {
				t.Errorf("SecurityScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPermissions_computeTier(t *testing.T) {
	tests := []struct {
		name string
		perm Permissions
		want PermissionTier
	}{
		{
			name: "enterprise with system extension",
			perm: Permissions{
				HasSystemExtension: true,
			},
			want: TierEnterprise,
		},
		{
			name: "standard with root and pf",
			perm: Permissions{
				HasRootAccess: true,
				CanUsePF:      true,
			},
			want: TierStandard,
		},
		{
			name: "minimal with nothing",
			perm: Permissions{},
			want: TierMinimal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.perm.computeTier()
			if tt.perm.Tier != tt.want {
				t.Errorf("computeTier() = %v, want %v", tt.perm.Tier, tt.want)
			}
		})
	}
}

func TestPermissions_AvailableFeatures(t *testing.T) {
	tests := []struct {
		tier         PermissionTier
		wantContains []string
	}{
		{
			tier:         TierEnterprise,
			wantContains: []string{"ESF", "NE", "tls_inspection"},
		},
		{
			tier:         TierStandard,
			wantContains: []string{"FSEvents", "pf"},
		},
		{
			tier:         TierMinimal,
			wantContains: []string{"command_logging"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			p := &Permissions{Tier: tt.tier}
			features := p.AvailableFeatures()
			featureStr := strings.Join(features, " ")
			for _, want := range tt.wantContains {
				if !strings.Contains(featureStr, want) {
					t.Errorf("AvailableFeatures() missing %q, got %v", want, features)
				}
			}
		})
	}
}

func TestPermissions_DisabledFeatures(t *testing.T) {
	tests := []struct {
		tier      PermissionTier
		wantEmpty bool
	}{
		{TierEnterprise, true},
		{TierStandard, false},
		{TierMinimal, false},
	}

	for _, tt := range tests {
		t.Run(tt.tier.String(), func(t *testing.T) {
			p := &Permissions{Tier: tt.tier}
			features := p.DisabledFeatures()
			if tt.wantEmpty && len(features) != 0 {
				t.Errorf("DisabledFeatures() = %v, want empty", features)
			}
			if !tt.wantEmpty && len(features) == 0 {
				t.Error("DisabledFeatures() is empty, want non-empty")
			}
		})
	}
}

func TestPermissions_computeMissingPermissions(t *testing.T) {
	p := &Permissions{
		HasSystemExtension: false,
		HasRootAccess:      false,
		HasFullDiskAccess:  false,
	}
	p.computeMissingPermissions()

	if len(p.MissingPermissions) == 0 {
		t.Error("computeMissingPermissions() returned empty list")
	}

	names := make(map[string]bool)
	for _, mp := range p.MissingPermissions {
		names[mp.Name] = true
	}

	expected := []string{"System Extension", "Root Access", "Full Disk Access"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("Missing expected permission: %s", name)
		}
	}

	// Verify system extension tip mentions the app bundle
	for _, mp := range p.MissingPermissions {
		if mp.Name == "System Extension" {
			if !strings.Contains(mp.HowToEnable, "app bundle") {
				t.Errorf("System Extension HowToEnable should mention app bundle, got: %s", mp.HowToEnable)
			}
		}
	}
}

func TestPermissions_LogStatus(t *testing.T) {
	p := &Permissions{
		HasSystemExtension: false,
		HasRootAccess:      true,
		CanUsePF:           true,
		HasFSEvents:        true,
		Tier:               TierStandard,
	}
	p.computeMissingPermissions()

	status := p.LogStatus()

	// Check for key sections
	if !strings.Contains(status, "macOS Permission Status") {
		t.Error("LogStatus() missing header")
	}
	if !strings.Contains(status, "Operating Tier") {
		t.Error("LogStatus() missing tier info")
	}
	if !strings.Contains(status, "Feature Availability") {
		t.Error("LogStatus() missing feature availability")
	}
	if !strings.Contains(status, "System Extension") {
		t.Error("LogStatus() missing System Extension section")
	}
}
