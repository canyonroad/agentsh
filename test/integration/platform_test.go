//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	_ "github.com/agentsh/agentsh/internal/platform/linux"
)

// TestPlatformCapabilities verifies platform detection and capability reporting.
func TestPlatformCapabilities(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	caps := p.Capabilities()
	t.Logf("Platform: %s", p.Name())
	t.Logf("FUSE: available=%v implementation=%s", caps.HasFUSE, caps.FUSEImplementation)
	t.Logf("Network: available=%v implementation=%s", caps.HasNetworkIntercept, caps.NetworkImplementation)
	t.Logf("Isolation: level=%v", caps.IsolationLevel)
	t.Logf("Seccomp: %v", caps.HasSeccomp)
	t.Logf("Cgroups: %v", caps.HasCgroups)

	// Platform name must be non-empty
	if p.Name() == "" {
		t.Error("platform name must not be empty")
	}
}

// TestPlatformWithOptions verifies platform creation with config options.
func TestPlatformWithOptions(t *testing.T) {
	tests := []struct {
		name string
		opts platform.PlatformOptions
	}{
		{
			name: "auto mode",
			opts: platform.PlatformOptions{Mode: "auto"},
		},
		{
			name: "empty mode defaults to auto",
			opts: platform.PlatformOptions{Mode: ""},
		},
		{
			name: "explicit linux mode",
			opts: platform.PlatformOptions{Mode: "linux"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := platform.NewWithOptions(tt.opts)
			if err != nil {
				t.Fatalf("NewWithOptions failed: %v", err)
			}
			if p == nil {
				t.Fatal("platform is nil")
			}
			t.Logf("Created platform: %s", p.Name())
		})
	}
}

// TestFilesystemInterceptor verifies filesystem interceptor availability.
func TestFilesystemInterceptor(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	fs := p.Filesystem()
	if fs == nil {
		t.Fatal("Filesystem() returned nil")
	}

	t.Logf("Filesystem available: %v", fs.Available())
	t.Logf("Filesystem implementation: %s", fs.Implementation())

	caps := p.Capabilities()
	if caps.HasFUSE && !fs.Available() {
		t.Error("capabilities reports HasFUSE but Filesystem not available")
	}
}

// TestNetworkInterceptor verifies network interceptor availability.
func TestNetworkInterceptor(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	net := p.Network()
	if net == nil {
		t.Fatal("Network() returned nil")
	}

	t.Logf("Network available: %v", net.Available())
	t.Logf("Network implementation: %s", net.Implementation())

	caps := p.Capabilities()
	if caps.HasNetworkIntercept && !net.Available() {
		t.Error("capabilities reports HasNetworkIntercept but Network not available")
	}
}

// TestSandboxManager verifies sandbox manager availability.
func TestSandboxManager(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	sm := p.Sandbox()
	if sm == nil {
		t.Fatal("Sandbox() returned nil")
	}

	t.Logf("Sandbox available: %v", sm.Available())
	t.Logf("Sandbox isolation level: %v", sm.IsolationLevel())

	caps := p.Capabilities()
	if caps.IsolationLevel != sm.IsolationLevel() {
		t.Errorf("capabilities isolation level %v != sandbox isolation level %v",
			caps.IsolationLevel, sm.IsolationLevel())
	}
}

// TestResourceLimiter verifies resource limiter availability.
func TestResourceLimiter(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	rl := p.Resources()
	if rl == nil {
		t.Fatal("Resources() returned nil")
	}

	t.Logf("Resources available: %v", rl.Available())
	t.Logf("Supported limits: %v", rl.SupportedLimits())
}

// TestSandboxCreate tests sandbox creation (if available).
func TestSandboxCreate(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	sm := p.Sandbox()
	if !sm.Available() {
		t.Skip("sandbox not available on this platform")
	}

	tmpDir := t.TempDir()
	sandbox, err := sm.Create(platform.SandboxConfig{
		Name:          "test-sandbox",
		WorkspacePath: tmpDir,
	})
	if err != nil {
		t.Fatalf("sandbox creation failed: %v", err)
	}
	defer sandbox.Close()

	if sandbox.ID() == "" {
		t.Error("sandbox ID must not be empty")
	}
	t.Logf("Created sandbox: %s", sandbox.ID())
}

// TestSandboxExecute tests command execution in sandbox.
func TestSandboxExecute(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	sm := p.Sandbox()
	if !sm.Available() {
		t.Skip("sandbox not available on this platform")
	}

	tmpDir := t.TempDir()
	sandbox, err := sm.Create(platform.SandboxConfig{
		Name:          "test-exec",
		WorkspacePath: tmpDir,
	})
	if err != nil {
		t.Fatalf("sandbox creation failed: %v", err)
	}
	defer sandbox.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := sandbox.Execute(ctx, "echo", "hello")
	if err != nil {
		t.Fatalf("sandbox execute failed: %v", err)
	}

	t.Logf("Exit code: %d", result.ExitCode)
	t.Logf("Stdout: %s", string(result.Stdout))
	t.Logf("Stderr: %s", string(result.Stderr))

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

// TestPlatformInitializeShutdown tests platform lifecycle.
func TestPlatformInitializeShutdown(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	events := make(chan platform.IOEvent, 100)
	cfg := platform.Config{
		WorkspacePath: tmpDir,
		EventChannel:  events,
	}

	if err := p.Initialize(ctx, cfg); err != nil {
		t.Logf("Initialize returned: %v (may be expected for some platforms)", err)
	}

	if err := p.Shutdown(ctx); err != nil {
		t.Logf("Shutdown returned: %v (may be expected for some platforms)", err)
	}
}

// TestParsePlatformMode verifies mode parsing.
func TestParsePlatformMode(t *testing.T) {
	tests := []struct {
		input string
		want  platform.PlatformMode
	}{
		{"auto", platform.ModeAuto},
		{"", platform.ModeAuto},
		{"linux", platform.ModeLinuxNative},
		{"linux-native", platform.ModeLinuxNative},
		{"darwin", platform.ModeDarwinNative},
		{"darwin-native", platform.ModeDarwinNative},
		{"macos", platform.ModeDarwinNative},
		{"darwin-lima", platform.ModeDarwinLima},
		{"lima", platform.ModeDarwinLima},
		{"windows", platform.ModeWindowsNative},
		{"windows-native", platform.ModeWindowsNative},
		{"windows-wsl2", platform.ModeWindowsWSL2},
		{"wsl2", platform.ModeWindowsWSL2},
		{"wsl", platform.ModeWindowsWSL2},
		{"unknown", platform.ModeAuto},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := platform.ParsePlatformMode(tt.input)
			if got != tt.want {
				t.Errorf("ParsePlatformMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestDetect verifies platform detection.
func TestDetect(t *testing.T) {
	mode, caps, err := platform.Detect()
	if err != nil {
		t.Fatalf("Detect() failed: %v", err)
	}

	t.Logf("Detected mode: %v", mode)
	t.Logf("Capabilities: FUSE=%v Seccomp=%v Cgroups=%v Isolation=%v",
		caps.HasFUSE, caps.HasSeccomp, caps.HasCgroups, caps.IsolationLevel)

	if mode == platform.ModeAuto {
		t.Error("Detect() should return a concrete mode, not ModeAuto")
	}
}

// TestPlatformModeString verifies mode string conversion.
func TestPlatformModeString(t *testing.T) {
	tests := []struct {
		mode platform.PlatformMode
		want string
	}{
		{platform.ModeAuto, "auto"},
		{platform.ModeLinuxNative, "linux-native"},
		{platform.ModeDarwinNative, "darwin-native"},
		{platform.ModeDarwinLima, "darwin-lima"},
		{platform.ModeWindowsNative, "windows-native"},
		{platform.ModeWindowsWSL2, "windows-wsl2"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("PlatformMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

// TestResourceLimiterApply tests resource limit application (if available).
func TestResourceLimiterApply(t *testing.T) {
	p, err := platform.New()
	if err != nil {
		t.Fatalf("failed to create platform: %v", err)
	}

	rl := p.Resources()
	if !rl.Available() {
		t.Skip("resource limiter not available on this platform")
	}

	supported := rl.SupportedLimits()
	t.Logf("Supported limits: %v", supported)

	// Only apply if we have memory support
	hasMemory := false
	for _, s := range supported {
		if s == platform.ResourceMemory {
			hasMemory = true
			break
		}
	}

	if !hasMemory {
		t.Skip("memory limits not supported")
	}

	handle, err := rl.Apply(platform.ResourceConfig{
		Name:        "test-limits",
		MaxMemoryMB: 512,
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	defer handle.Release()

	stats := handle.Stats()
	t.Logf("Initial stats: MemoryMB=%d CPUPercent=%.2f", stats.MemoryMB, stats.CPUPercent)
}

// TestIsolationLevel verifies isolation level consistency.
func TestIsolationLevel(t *testing.T) {
	tests := []struct {
		level platform.IsolationLevel
		str   string
	}{
		{platform.IsolationNone, "none"},
		{platform.IsolationMinimal, "minimal"},
		{platform.IsolationPartial, "partial"},
		{platform.IsolationFull, "full"},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got := tt.level.String()
			if got != tt.str {
				t.Errorf("IsolationLevel(%d).String() = %q, want %q", tt.level, got, tt.str)
			}
		})
	}
}

// TestEventTypes verifies event type constants.
func TestEventTypes(t *testing.T) {
	events := []platform.EventType{
		platform.EventFileOpen,
		platform.EventFileRead,
		platform.EventFileWrite,
		platform.EventFileCreate,
		platform.EventFileDelete,
		platform.EventNetConnect,
		platform.EventDNSQuery,
		platform.EventEnvRead,
		platform.EventEnvList,
		platform.EventProcessExec,
	}

	for _, e := range events {
		if e == "" {
			t.Error("event type should not be empty")
		}
		t.Logf("EventType: %s", e)
	}
}

// TestFileOperation verifies file operation constants.
func TestFileOperation(t *testing.T) {
	ops := []platform.FileOperation{
		platform.FileOpRead,
		platform.FileOpWrite,
		platform.FileOpCreate,
		platform.FileOpDelete,
		platform.FileOpRename,
		platform.FileOpStat,
		platform.FileOpList,
	}

	for _, op := range ops {
		if op == "" {
			t.Error("file operation should not be empty")
		}
		t.Logf("FileOperation: %s", op)
	}
}

// TestEnvOperation verifies env operation constants.
func TestEnvOperation(t *testing.T) {
	ops := []platform.EnvOperation{
		platform.EnvOpRead,
		platform.EnvOpList,
		platform.EnvOpWrite,
		platform.EnvOpDelete,
	}

	for _, op := range ops {
		if op == "" {
			t.Error("env operation should not be empty")
		}
		t.Logf("EnvOperation: %s", op)
	}
}

// TestDecisionConstants verifies decision constants.
func TestDecisionConstants(t *testing.T) {
	if platform.DecisionAllow == "" {
		t.Error("DecisionAllow should not be empty")
	}
	if platform.DecisionDeny == "" {
		t.Error("DecisionDeny should not be empty")
	}
	if platform.DecisionApprove == "" {
		t.Error("DecisionApprove should not be empty")
	}
	if platform.DecisionRedirect == "" {
		t.Error("DecisionRedirect should not be empty")
	}

	t.Logf("Decisions: allow=%s deny=%s approve=%s redirect=%s",
		platform.DecisionAllow, platform.DecisionDeny,
		platform.DecisionApprove, platform.DecisionRedirect)
}
