//go:build linux

package capabilities

import (
	"testing"
)

func TestAlwaysDropCaps(t *testing.T) {
	// These must always be in the always-drop list
	required := []string{
		"CAP_SYS_ADMIN",
		"CAP_SYS_PTRACE",
		"CAP_SYS_MODULE",
		"CAP_DAC_OVERRIDE",
		"CAP_SETUID",
		"CAP_SETGID",
		"CAP_NET_ADMIN",
	}

	for _, cap := range required {
		if !isAlwaysDrop(cap) {
			t.Errorf("%s should be in always-drop list", cap)
		}
	}
}

func TestValidateAllowList(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		wantErr bool
	}{
		{
			name:    "empty allow list is valid",
			allow:   []string{},
			wantErr: false,
		},
		{
			name:    "CAP_NET_RAW is allowable",
			allow:   []string{"CAP_NET_RAW"},
			wantErr: false,
		},
		{
			name:    "CAP_SYS_ADMIN is never allowable",
			allow:   []string{"CAP_SYS_ADMIN"},
			wantErr: true,
		},
		{
			name:    "CAP_SYS_PTRACE is never allowable",
			allow:   []string{"CAP_SYS_PTRACE"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCapabilityAllowList(tt.allow)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCapabilityAllowList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsAlwaysDrop_CaseInsensitive(t *testing.T) {
	// Should work with various case formats
	tests := []struct {
		cap      string
		expected bool
	}{
		{"CAP_SYS_ADMIN", true},
		{"cap_sys_admin", true},
		{"Cap_Sys_Admin", true},
		{"SYS_ADMIN", true},  // Without CAP_ prefix
		{"sys_admin", true},  // Without CAP_ prefix, lowercase
		{"CAP_NET_RAW", false},
		{"NET_RAW", false},
	}

	for _, tt := range tests {
		t.Run(tt.cap, func(t *testing.T) {
			result := isAlwaysDrop(tt.cap)
			if result != tt.expected {
				t.Errorf("isAlwaysDrop(%q) = %v, want %v", tt.cap, result, tt.expected)
			}
		})
	}
}
