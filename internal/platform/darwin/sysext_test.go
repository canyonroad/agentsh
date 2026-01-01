//go:build darwin

package darwin

import (
	"testing"
)

func TestNewSysExtManager(t *testing.T) {
	m := NewSysExtManager()
	if m == nil {
		t.Fatal("NewSysExtManager() returned nil")
	}
	if m.bundleID != "com.agentsh.sysext" {
		t.Errorf("bundleID = %q, want %q", m.bundleID, "com.agentsh.sysext")
	}
}

func TestSysExtManager_Status(t *testing.T) {
	m := NewSysExtManager()

	status, err := m.Status()
	if err != nil {
		t.Fatalf("Status() error = %v, want nil (errors go in status.Error)", err)
	}
	if status == nil {
		t.Fatal("Status() returned nil status")
	}
	if status.BundleID != "com.agentsh.sysext" {
		t.Errorf("BundleID = %q, want %q", status.BundleID, "com.agentsh.sysext")
	}
}

func TestSysExtManager_Status_NeverReturnsError(t *testing.T) {
	// The Status method should never return an error - errors go in status.Error field
	m := &SysExtManager{
		bundlePath: "",
		bundleID:   "com.agentsh.sysext",
	}

	status, err := m.Status()
	if err != nil {
		t.Fatalf("Status() returned error %v, want nil (errors should be in status.Error)", err)
	}
	if status.Error == "" {
		t.Error("Expected status.Error to contain error message for missing bundle")
	}
}

func TestSysExtManager_Install_NoBundleError(t *testing.T) {
	m := &SysExtManager{
		bundlePath: "",
		bundleID:   "com.agentsh.sysext",
	}

	err := m.Install()
	if err == nil {
		t.Fatal("Install() should error when bundle not found")
	}
}

func TestSysExtManager_Uninstall_NotImplemented(t *testing.T) {
	m := NewSysExtManager()

	err := m.Uninstall()
	if err == nil {
		t.Fatal("Uninstall() should return error (not implemented)")
	}
}

func TestFindAppBundle_FromWithinBundle(t *testing.T) {
	tests := []struct {
		name     string
		execPath string
		want     string
	}{
		{
			name:     "from within app bundle Contents/MacOS",
			execPath: "/Applications/AgentSH.app/Contents/MacOS/agentsh",
			want:     "/Applications/AgentSH.app",
		},
		{
			name:     "from within app bundle nested",
			execPath: "/some/path/AgentSH.app/Contents/Resources/bin/tool",
			want:     "/some/path/AgentSH.app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findAppBundle(tt.execPath)
			if got != tt.want {
				t.Errorf("findAppBundle(%q) = %q, want %q", tt.execPath, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		substr string
		want   bool
	}{
		{
			name:   "empty string and empty substr",
			s:      "",
			substr: "",
			want:   true,
		},
		{
			name:   "empty string with non-empty substr",
			s:      "",
			substr: "foo",
			want:   false,
		},
		{
			name:   "non-empty string with empty substr",
			s:      "foo",
			substr: "",
			want:   true,
		},
		{
			name:   "substr at start",
			s:      "hello world",
			substr: "hello",
			want:   true,
		},
		{
			name:   "substr at end",
			s:      "hello world",
			substr: "world",
			want:   true,
		},
		{
			name:   "substr in middle",
			s:      "hello world",
			substr: "lo wo",
			want:   true,
		},
		{
			name:   "substr not present",
			s:      "hello world",
			substr: "foo",
			want:   false,
		},
		{
			name:   "substr longer than string",
			s:      "hi",
			substr: "hello",
			want:   false,
		},
		{
			name:   "exact match",
			s:      "hello",
			substr: "hello",
			want:   true,
		},
		{
			name:   "real systemextensionsctl output with bundle ID",
			s:      "1 extension(s)\n--- com.apple.system_extension.endpoint_security\ncom.agentsh.sysext	team_id	activated enabled",
			substr: "com.agentsh.sysext",
			want:   true,
		},
		{
			name:   "real systemextensionsctl output check running state",
			s:      "com.agentsh.sysext	team_id	activated enabled",
			substr: "activated enabled",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestSysExtStatus_JSONTags(t *testing.T) {
	// Verify that SysExtStatus has the expected structure
	status := SysExtStatus{
		Installed:   true,
		Running:     true,
		Version:     "1.0.0",
		BundleID:    "com.agentsh.sysext",
		ExtensionID: "ext-123",
		Error:       "",
	}

	// Just verify the struct can be created with all fields
	if !status.Installed {
		t.Error("Installed should be true")
	}
	if !status.Running {
		t.Error("Running should be true")
	}
	if status.Version != "1.0.0" {
		t.Error("Version mismatch")
	}
	if status.BundleID != "com.agentsh.sysext" {
		t.Error("BundleID mismatch")
	}
	if status.ExtensionID != "ext-123" {
		t.Error("ExtensionID mismatch")
	}
}
