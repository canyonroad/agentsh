package cli

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDaemonStatus(t *testing.T) {
	cmd := newDaemonStatusCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()

	// Should show status and session info
	if !strings.Contains(output, "Daemon status:") {
		t.Errorf("expected 'Daemon status:' in output, got: %s", output)
	}
}

func TestDaemonStatus_JSON(t *testing.T) {
	cmd := newDaemonStatusCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--json"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	output := buf.String()

	// Should be valid JSON with expected fields
	if !strings.Contains(output, `"status":`) {
		t.Errorf("expected JSON with status field, got: %s", output)
	}
	if !strings.Contains(output, `"computer_name":`) {
		t.Errorf("expected JSON with computer_name field, got: %s", output)
	}
}

func TestGetActiveIPs(t *testing.T) {
	ips := getActiveIPs()

	// Should return at least empty slice, not nil
	if ips == nil {
		t.Error("expected non-nil slice")
	}

	// Note: We can't guarantee any IPs will be returned in test environments,
	// but if any are returned, they should be valid
	for _, ip := range ips {
		// Should not contain loopback
		if strings.HasPrefix(ip, "127.") || ip == "::1" {
			t.Errorf("should not contain loopback address: %s", ip)
		}
		// Should not contain link-local
		if strings.HasPrefix(ip, "169.254.") || strings.HasPrefix(ip, "fe80:") {
			t.Errorf("should not contain link-local address: %s", ip)
		}
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		seconds  int
		expected string
	}{
		{"under minute", 45, "45s"},
		{"one minute", 60, "1m 0s"},
		{"minutes and seconds", 125, "2m 5s"},
		{"one hour", 3600, "1h 0m"},
		{"hours and minutes", 3720, "1h 2m"},
		{"one day", 86400, "1d 0h"},
		{"days and hours", 90000, "1d 1h"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Convert seconds to duration
			d := time.Duration(tc.seconds) * time.Second
			result := formatUptime(d)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()

	if id1 == "" {
		t.Error("session ID should not be empty")
	}

	// IDs should be unique (different timestamps)
	if id1 == id2 {
		t.Error("session IDs should be unique")
	}

	// Should contain hostname
	hostname, _ := os.Hostname()
	if hostname != "" && !strings.Contains(id1, hostname) {
		t.Errorf("session ID should contain hostname %q, got %q", hostname, id1)
	}
}

func TestDaemonInstall_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test only runs on Linux")
	}

	// This test just verifies the command runs without panicking
	// We can't easily test the actual install without mocking user.Current()
	// and filesystem operations

	cmd := newDaemonInstallCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Just check help works
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	if err != nil {
		t.Errorf("help should not error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "systemd") {
		t.Errorf("expected 'systemd' in help output, got: %s", output)
	}
}

func TestDaemonUninstall_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test only runs on Linux")
	}

	// This test just verifies the command runs without panicking
	cmd := newDaemonUninstallCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Just check help works
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	if err != nil {
		t.Errorf("help should not error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Remove") {
		t.Errorf("expected 'Remove' in help output, got: %s", output)
	}
}

func TestSystemdServiceTemplate(t *testing.T) {
	// Verify the template has required sections
	if !strings.Contains(systemdServiceTemplate, "[Unit]") {
		t.Error("template should have [Unit] section")
	}
	if !strings.Contains(systemdServiceTemplate, "[Service]") {
		t.Error("template should have [Service] section")
	}
	if !strings.Contains(systemdServiceTemplate, "[Install]") {
		t.Error("template should have [Install] section")
	}
	if !strings.Contains(systemdServiceTemplate, "ExecStart=") {
		t.Error("template should have ExecStart directive")
	}
	if !strings.Contains(systemdServiceTemplate, "Restart=") {
		t.Error("template should have Restart directive")
	}
}

func TestLaunchdPlistTemplate(t *testing.T) {
	// Verify the template has required elements
	if !strings.Contains(launchdPlistTemplate, "Label") {
		t.Error("template should have Label key")
	}
	if !strings.Contains(launchdPlistTemplate, "ProgramArguments") {
		t.Error("template should have ProgramArguments key")
	}
	if !strings.Contains(launchdPlistTemplate, "RunAtLoad") {
		t.Error("template should have RunAtLoad key")
	}
	if !strings.Contains(launchdPlistTemplate, "com.agentsh.daemon") {
		t.Error("template should have correct label")
	}
}

func TestPNACLSession(t *testing.T) {
	session := PNACLSession{
		ID:           "test-session-123",
		ComputerName: "testhost",
		ComputerIP:   []string{"192.168.1.100", "10.0.0.50"},
		Username:     "testuser",
		UserID:       "1000",
		Status:       "running",
		EventCount:   42,
		Version:      "1.0.0",
		Platform:     "linux/amd64",
	}

	// Verify fields are set correctly
	if session.ID != "test-session-123" {
		t.Errorf("expected ID 'test-session-123', got %s", session.ID)
	}
	if session.ComputerName != "testhost" {
		t.Errorf("expected ComputerName 'testhost', got %s", session.ComputerName)
	}
	if len(session.ComputerIP) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(session.ComputerIP))
	}
	if session.Username != "testuser" {
		t.Errorf("expected Username 'testuser', got %s", session.Username)
	}
}

func TestGetCurrentSession(t *testing.T) {
	cmd := newDaemonStatusCmd()
	session, err := getCurrentSession(cmd)

	// Should not error even if daemon is not running
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have populated basic fields
	if session.ComputerName == "" {
		// Hostname might fail in some environments, that's OK
		t.Log("hostname not available")
	}

	// Username should be populated
	if session.Username == "" {
		t.Log("username not available")
	}

	// Platform should be set
	expectedPlatform := runtime.GOOS + "/" + runtime.GOARCH
	if session.Platform != expectedPlatform {
		t.Errorf("expected platform %q, got %q", expectedPlatform, session.Platform)
	}
}
