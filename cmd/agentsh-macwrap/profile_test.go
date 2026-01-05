//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestGenerateProfile_DefaultDeny(t *testing.T) {
	cfg := &WrapperConfig{
		WorkspacePath: "/Users/test/project",
		MachServices: MachServicesConfig{
			DefaultAction: "deny",
			Allow: []string{
				"com.apple.system.logger",
				"com.apple.CoreServices.coreservicesd",
			},
			AllowPrefixes: []string{"com.apple.cfprefsd."},
		},
	}

	profile := generateProfile(cfg)

	// Should start with version
	if !strings.HasPrefix(profile, "(version 1)") {
		t.Error("profile should start with (version 1)")
	}

	// Should have deny default
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile should have (deny default)")
	}

	// Should have specific allows
	if !strings.Contains(profile, `(global-name "com.apple.system.logger")`) {
		t.Error("missing allowed service")
	}

	// Should have prefix allow
	if !strings.Contains(profile, `(global-name-prefix "com.apple.cfprefsd.")`) {
		t.Error("missing allowed prefix")
	}

	// Should have workspace
	if !strings.Contains(profile, `(subpath "/Users/test/project")`) {
		t.Error("missing workspace path")
	}

	// Should NOT have blanket allow mach-lookup
	if strings.Contains(profile, "(allow mach-lookup)") &&
		!strings.Contains(profile, "(allow mach-lookup\n") {
		t.Error("should not have blanket mach-lookup allow in deny mode")
	}
}

func TestGenerateProfile_DefaultAllow(t *testing.T) {
	cfg := &WrapperConfig{
		MachServices: MachServicesConfig{
			DefaultAction: "allow",
			Block:         []string{"com.apple.security.authhost"},
			BlockPrefixes: []string{"com.apple.accessibility."},
		},
	}

	profile := generateProfile(cfg)

	// Should have blanket allow
	if !strings.Contains(profile, "(allow mach-lookup)") {
		t.Error("should have blanket mach-lookup allow")
	}

	// Should have deny rules
	if !strings.Contains(profile, "(deny mach-lookup") {
		t.Error("missing deny rules")
	}

	if !strings.Contains(profile, `(global-name "com.apple.security.authhost")`) {
		t.Error("missing blocked service")
	}
}

func TestGenerateProfile_PathEscaping(t *testing.T) {
	cfg := &WrapperConfig{
		WorkspacePath: `/Users/test/path with "quotes"`,
		MachServices:  MachServicesConfig{DefaultAction: "allow"},
	}

	profile := generateProfile(cfg)

	if !strings.Contains(profile, `path with \"quotes\"`) {
		t.Error("quotes not properly escaped")
	}
}

func TestGenerateProfile_NetworkAllowed(t *testing.T) {
	cfg := &WrapperConfig{
		AllowNetwork: true,
		MachServices: MachServicesConfig{DefaultAction: "allow"},
	}

	profile := generateProfile(cfg)

	if !strings.Contains(profile, "(allow network*)") {
		t.Error("should allow network when AllowNetwork is true")
	}
}
