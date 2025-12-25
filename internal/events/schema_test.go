package events

import (
	"strings"
	"testing"
)

func TestEventTypes(t *testing.T) {
	// Verify all event types have categories
	for _, et := range AllEventTypes {
		if _, ok := EventCategory[et]; !ok {
			t.Errorf("Event type %q has no category", et)
		}
	}
}

func TestEventCategory(t *testing.T) {
	tests := []struct {
		eventType EventType
		category  string
	}{
		{EventFileOpen, "file"},
		{EventNetConnect, "network"},
		{EventProcessSpawn, "process"},
		{EventShellInvoke, "shell"},
		{EventCommandRedirect, "command"},
		{EventResourceLimitSet, "resource"},
		{EventUnixSocketConnect, "ipc"},
	}

	for _, tt := range tests {
		if got := EventCategory[tt.eventType]; got != tt.category {
			t.Errorf("EventCategory[%q] = %q, want %q", tt.eventType, got, tt.category)
		}
	}
}

func TestRuntimeContext(t *testing.T) {
	ctx := DetectRuntimeContext()

	if ctx.OS == "" {
		t.Error("OS should not be empty")
	}
	if ctx.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if ctx.EventSchemaVersion != "1.0" {
		t.Errorf("EventSchemaVersion = %q, want 1.0", ctx.EventSchemaVersion)
	}
}

func TestEventFactory(t *testing.T) {
	ctx := &RuntimeContext{
		Hostname:           "test-host",
		OS:                 "linux",
		Arch:               "amd64",
		EventSchemaVersion: "1.0",
	}

	factory := NewEventFactory(ctx, "session-123", nil)
	event := factory.NewEvent(EventFileOpen, 1234)

	if event.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want test-host", event.Hostname)
	}
	if event.OS != "linux" {
		t.Errorf("OS = %q, want linux", event.OS)
	}
	if event.SessionID != "session-123" {
		t.Errorf("SessionID = %q, want session-123", event.SessionID)
	}
	if event.PID != 1234 {
		t.Errorf("PID = %d, want 1234", event.PID)
	}
	if event.Type != EventFileOpen {
		t.Errorf("Type = %q, want file_open", event.Type)
	}
	if event.Category != "file" {
		t.Errorf("Category = %q, want file", event.Category)
	}
	if event.EventID == "" {
		t.Error("EventID should not be empty")
	}
	if event.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
	if event.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", event.Sequence)
	}
}

func TestEventFactorySequence(t *testing.T) {
	ctx := &RuntimeContext{OS: "linux", Arch: "amd64", EventSchemaVersion: "1.0"}
	factory := NewEventFactory(ctx, "session-123", nil)

	e1 := factory.NewEvent(EventFileOpen, 1)
	e2 := factory.NewEvent(EventFileRead, 2)
	e3 := factory.NewEvent(EventFileWrite, 3)

	if e1.Sequence != 1 {
		t.Errorf("e1.Sequence = %d, want 1", e1.Sequence)
	}
	if e2.Sequence != 2 {
		t.Errorf("e2.Sequence = %d, want 2", e2.Sequence)
	}
	if e3.Sequence != 3 {
		t.Errorf("e3.Sequence = %d, want 3", e3.Sequence)
	}
}

func TestSanitizer(t *testing.T) {
	s := NewDefaultSanitizer()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/home/user/.ssh/id_rsa", true},
		{"/home/user/.aws/credentials", true},
		{"/etc/passwd", false},
		{"/var/log/app.log", false},
		{"/home/user/.kube/config", true},
		{"/home/user/project/password.txt", true},
		{"/home/user/project/token.json", true},
	}

	for _, tt := range tests {
		if got := s.IsSensitivePath(tt.path); got != tt.expected {
			t.Errorf("IsSensitivePath(%q) = %v, want %v", tt.path, got, tt.expected)
		}
	}
}

func TestSanitizerPath(t *testing.T) {
	s := NewDefaultSanitizer()

	path := "/home/user/.ssh/id_rsa"
	sanitized, fields := s.SanitizePath(path)

	if !strings.Contains(sanitized, "[REDACTED]") {
		t.Errorf("Expected sanitized path to contain [REDACTED], got %q", sanitized)
	}
	if len(fields) == 0 {
		t.Error("Expected fields to be non-empty")
	}
}

func TestSanitizerCmdline(t *testing.T) {
	s := NewDefaultSanitizer()

	cmdline := []string{"mysql", "-u", "root", "--password=secret123", "dbname"}
	sanitized := s.SanitizeCmdline(cmdline)

	for i, arg := range sanitized {
		if strings.Contains(arg, "secret123") {
			t.Errorf("Arg %d should not contain secret: %q", i, arg)
		}
	}
}

func TestSanitizerEnvVar(t *testing.T) {
	s := NewDefaultSanitizer()

	tests := []struct {
		name     string
		expected bool
	}{
		{"AWS_SECRET_ACCESS_KEY", true},
		{"DATABASE_PASSWORD", true},
		{"API_KEY", true},
		{"GITHUB_TOKEN", true},
		{"PATH", false},
		{"HOME", false},
		{"USER", false},
	}

	for _, tt := range tests {
		if got := s.ShouldSanitizeEnvVar(tt.name); got != tt.expected {
			t.Errorf("ShouldSanitizeEnvVar(%q) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

func TestEventConfig(t *testing.T) {
	config := DefaultEventConfig()

	if !config.IncludeNetworkInfo {
		t.Error("IncludeNetworkInfo should default to true")
	}
	if config.IncludeMACAddress {
		t.Error("IncludeMACAddress should default to false")
	}
	if !config.SanitizePaths {
		t.Error("SanitizePaths should default to true")
	}
}

func TestBaseEvent(t *testing.T) {
	event := BaseEvent{
		Hostname:  "test-host",
		MachineID: "machine-123",
		OS:        "linux",
		Arch:      "amd64",
		Type:      EventFileOpen,
		Category:  "file",
		PID:       1234,
		SessionID: "session-123",
	}

	if event.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want test-host", event.Hostname)
	}
	if event.Type != EventFileOpen {
		t.Errorf("Type = %q, want file_open", event.Type)
	}
}

func TestShellInvokeEvent(t *testing.T) {
	event := ShellInvokeEvent{
		Shell:       "bash",
		InvokedAs:   "/bin/bash",
		Args:        []string{"-c", "echo hello"},
		Mode:        "command",
		Command:     "echo hello",
		Intercepted: true,
		Strategy:    "binary_replace",
	}

	if event.Shell != "bash" {
		t.Errorf("Shell = %q, want bash", event.Shell)
	}
	if !event.Intercepted {
		t.Error("Intercepted should be true")
	}
}

func TestResourceLimits(t *testing.T) {
	limits := ResourceLimits{
		MaxMemoryMB:     2048,
		CPUQuotaPercent: 80,
		MaxProcesses:    100,
	}

	if limits.MaxMemoryMB != 2048 {
		t.Errorf("MaxMemoryMB = %d, want 2048", limits.MaxMemoryMB)
	}
	if limits.CPUQuotaPercent != 80 {
		t.Errorf("CPUQuotaPercent = %d, want 80", limits.CPUQuotaPercent)
	}
}

func TestProcessSpawnEvent(t *testing.T) {
	event := ProcessSpawnEvent{
		ChildPID:  1235,
		ChildComm: "node",
		ParentPID: 1234,
		Depth:     2,
		Expected:  true,
	}

	if event.ChildPID != 1235 {
		t.Errorf("ChildPID = %d, want 1235", event.ChildPID)
	}
	if event.Depth != 2 {
		t.Errorf("Depth = %d, want 2", event.Depth)
	}
}

func TestUnixSocketEvent(t *testing.T) {
	event := UnixSocketEvent{
		Operation:  "connect",
		SocketType: "stream",
		Path:       "/var/run/docker.sock",
		Service:    "docker",
		Method:     "seccomp",
	}

	if event.Path != "/var/run/docker.sock" {
		t.Errorf("Path = %q, want /var/run/docker.sock", event.Path)
	}
	if event.Service != "docker" {
		t.Errorf("Service = %q, want docker", event.Service)
	}
}
