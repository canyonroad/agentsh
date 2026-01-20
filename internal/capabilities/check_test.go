//go:build linux

package capabilities

import (
	"errors"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestCheckAll_NoConfig(t *testing.T) {
	err := CheckAll(nil)
	if err != nil {
		t.Fatalf("expected nil error when config is nil, got: %v", err)
	}
}

func TestCheckAll_AllDisabled(t *testing.T) {
	// Create config with all features disabled
	disabled := false
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: &disabled,
			},
			Seccomp: config.SandboxSeccompConfig{
				Enabled: false,
			},
			Cgroups: config.SandboxCgroupsConfig{
				Enabled: false,
			},
			Network: config.SandboxNetworkConfig{
				EBPF: config.SandboxEBPFConfig{
					Enabled: false,
				},
			},
		},
	}

	err := CheckAll(cfg)
	if err != nil {
		t.Fatalf("expected nil error when all features disabled, got: %v", err)
	}
}

func TestCheckAll_SeccompUserNotify_Available(t *testing.T) {
	// Save and restore original
	orig := checkSeccompUserNotify
	origBinary := checkWrapperBinary
	defer func() {
		checkSeccompUserNotify = orig
		checkWrapperBinary = origBinary
	}()

	// Mock to return success
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{
			Feature:   "seccomp-user-notify",
			Available: true,
		}
	}
	// Mock binary check to pass
	checkWrapperBinary = func(string) CheckResult {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: true,
		}
	}

	// Create config with unix_sockets enabled
	enabled := true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: &enabled,
			},
		},
	}

	err := CheckAll(cfg)
	if err != nil {
		t.Fatalf("expected nil error when seccomp available, got: %v", err)
	}
}

func TestCheckAll_SeccompUserNotify_Available_ViaSeccompEnabled(t *testing.T) {
	// Save and restore original
	orig := checkSeccompUserNotify
	defer func() { checkSeccompUserNotify = orig }()

	// Mock to return success
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{
			Feature:   "seccomp-user-notify",
			Available: true,
		}
	}

	// Create config with seccomp.enabled = true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Seccomp: config.SandboxSeccompConfig{
				Enabled: true,
			},
		},
	}

	err := CheckAll(cfg)
	if err != nil {
		t.Fatalf("expected nil error when seccomp available, got: %v", err)
	}
}

func TestCheckAll_SeccompUserNotify_Unavailable(t *testing.T) {
	// Save and restore original
	orig := checkSeccompUserNotify
	origBinary := checkWrapperBinary
	defer func() {
		checkSeccompUserNotify = orig
		checkWrapperBinary = origBinary
	}()

	// Mock to return failure
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{
			Feature:   "seccomp-user-notify",
			Available: false,
			Error:     errors.New("kernel does not support SECCOMP_RET_USER_NOTIF (requires kernel 5.0+)"),
		}
	}
	// Mock binary check to pass (so we can test seccomp failure in isolation)
	checkWrapperBinary = func(string) CheckResult {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: true,
		}
	}

	// Create config with unix_sockets enabled
	enabled := true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: &enabled,
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when seccomp unavailable")
	}

	errStr := err.Error()

	// Verify error message contains expected components
	if !strings.Contains(errStr, "seccomp-user-notify") {
		t.Errorf("error should mention feature, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.unix_sockets.enabled") {
		t.Errorf("error should mention config key, got: %v", err)
	}
	if !strings.Contains(errStr, "kernel does not support") {
		t.Errorf("error should mention the cause, got: %v", err)
	}
	if !strings.Contains(errStr, "To fix:") {
		t.Errorf("error should include suggestion, got: %v", err)
	}
}

func TestCheckAll_Ptrace_Unavailable(t *testing.T) {
	// Save and restore originals
	origPtrace := checkPtrace
	origCgroups := checkCgroupsV2
	defer func() {
		checkPtrace = origPtrace
		checkCgroupsV2 = origCgroups
	}()

	// Mock cgroups to pass (so we can test ptrace failure in isolation)
	checkCgroupsV2 = func() CheckResult {
		return CheckResult{
			Feature:   "cgroups-v2",
			Available: true,
		}
	}

	// Mock ptrace to return failure
	checkPtrace = func() CheckResult {
		return CheckResult{
			Feature:   "ptrace",
			Available: false,
			Error:     errors.New("ptrace not available: operation not permitted"),
		}
	}

	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Cgroups: config.SandboxCgroupsConfig{
				Enabled: true,
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when ptrace unavailable")
	}

	errStr := err.Error()

	if !strings.Contains(errStr, "ptrace") {
		t.Errorf("error should mention feature, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.cgroups.enabled") {
		t.Errorf("error should mention config key, got: %v", err)
	}
	if !strings.Contains(errStr, "operation not permitted") {
		t.Errorf("error should mention the cause, got: %v", err)
	}
}

func TestCheckAll_CgroupsV2_Unavailable(t *testing.T) {
	// Save and restore originals
	origPtrace := checkPtrace
	origCgroups := checkCgroupsV2
	defer func() {
		checkPtrace = origPtrace
		checkCgroupsV2 = origCgroups
	}()

	// Mock ptrace to pass
	checkPtrace = func() CheckResult {
		return CheckResult{
			Feature:   "ptrace",
			Available: true,
		}
	}

	// Mock cgroups v2 to return failure
	checkCgroupsV2 = func() CheckResult {
		return CheckResult{
			Feature:   "cgroups-v2",
			Available: false,
			Error:     errors.New("cgroups v2 not available: /sys/fs/cgroup/cgroup.controllers not found"),
		}
	}

	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Cgroups: config.SandboxCgroupsConfig{
				Enabled: true,
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when cgroups v2 unavailable")
	}

	errStr := err.Error()

	if !strings.Contains(errStr, "cgroups-v2") {
		t.Errorf("error should mention feature, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.cgroups.enabled") {
		t.Errorf("error should mention config key, got: %v", err)
	}
	if !strings.Contains(errStr, "cgroup.controllers") {
		t.Errorf("error should mention the cause, got: %v", err)
	}
}

func TestCheckAll_EBPF_Unavailable(t *testing.T) {
	// Save and restore original
	orig := checkeBPF
	defer func() { checkeBPF = orig }()

	// Mock to return failure
	checkeBPF = func() CheckResult {
		return CheckResult{
			Feature:   "ebpf",
			Available: false,
			Error:     errors.New("eBPF not available: permission denied (requires CAP_BPF or CAP_SYS_ADMIN)"),
		}
	}

	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Network: config.SandboxNetworkConfig{
				EBPF: config.SandboxEBPFConfig{
					Enabled: true,
				},
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when eBPF unavailable")
	}

	errStr := err.Error()

	if !strings.Contains(errStr, "ebpf") {
		t.Errorf("error should mention feature, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.network.ebpf.enabled") {
		t.Errorf("error should mention config key, got: %v", err)
	}
	if !strings.Contains(errStr, "permission denied") {
		t.Errorf("error should mention the cause, got: %v", err)
	}
}

func TestCheckAll_MultipleFailures(t *testing.T) {
	// Save and restore originals
	origSeccomp := checkSeccompUserNotify
	origPtrace := checkPtrace
	origCgroups := checkCgroupsV2
	origEBPF := checkeBPF
	origBinary := checkWrapperBinary
	defer func() {
		checkSeccompUserNotify = origSeccomp
		checkPtrace = origPtrace
		checkCgroupsV2 = origCgroups
		checkeBPF = origEBPF
		checkWrapperBinary = origBinary
	}()

	// Mock all to return failure
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{
			Feature:   "seccomp-user-notify",
			Available: false,
			Error:     errors.New("kernel does not support SECCOMP_RET_USER_NOTIF"),
		}
	}

	checkPtrace = func() CheckResult {
		return CheckResult{
			Feature:   "ptrace",
			Available: false,
			Error:     errors.New("ptrace not available"),
		}
	}

	checkCgroupsV2 = func() CheckResult {
		return CheckResult{
			Feature:   "cgroups-v2",
			Available: false,
			Error:     errors.New("cgroups v2 not available"),
		}
	}

	checkeBPF = func() CheckResult {
		return CheckResult{
			Feature:   "ebpf",
			Available: false,
			Error:     errors.New("eBPF not available"),
		}
	}

	// Mock binary check to pass (so we can test other failures in isolation)
	checkWrapperBinary = func(string) CheckResult {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: true,
		}
	}

	// Enable all features
	enabled := true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: &enabled,
			},
			Cgroups: config.SandboxCgroupsConfig{
				Enabled: true,
			},
			Network: config.SandboxNetworkConfig{
				EBPF: config.SandboxEBPFConfig{
					Enabled: true,
				},
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when multiple features unavailable")
	}

	errStr := err.Error()

	// Verify all failures are reported
	if !strings.Contains(errStr, "seccomp-user-notify") {
		t.Errorf("error should mention seccomp-user-notify, got: %v", err)
	}
	if !strings.Contains(errStr, "ptrace") {
		t.Errorf("error should mention ptrace, got: %v", err)
	}
	if !strings.Contains(errStr, "cgroups-v2") {
		t.Errorf("error should mention cgroups-v2, got: %v", err)
	}
	if !strings.Contains(errStr, "ebpf") {
		t.Errorf("error should mention ebpf, got: %v", err)
	}

	// Verify multiple config keys are mentioned
	if !strings.Contains(errStr, "sandbox.unix_sockets.enabled") {
		t.Errorf("error should mention sandbox.unix_sockets.enabled, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.cgroups.enabled") {
		t.Errorf("error should mention sandbox.cgroups.enabled, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.network.ebpf.enabled") {
		t.Errorf("error should mention sandbox.network.ebpf.enabled, got: %v", err)
	}
}

func TestCheckAll_ErrorFormat(t *testing.T) {
	// Save and restore original
	orig := checkSeccompUserNotify
	origBinary := checkWrapperBinary
	defer func() {
		checkSeccompUserNotify = orig
		checkWrapperBinary = origBinary
	}()

	// Mock to return failure with specific error
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{
			Feature:   "seccomp-user-notify",
			Available: false,
			Error:     errors.New("test error message"),
		}
	}
	// Mock binary check to pass
	checkWrapperBinary = func(string) CheckResult {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: true,
		}
	}

	enabled := true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: &enabled,
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error")
	}

	errStr := err.Error()

	// Verify the error format includes all expected components
	expectedParts := []struct {
		name  string
		value string
	}{
		{"header", "agentsh: capability check failed"},
		{"Feature label", "Feature:"},
		{"Feature value", "seccomp-user-notify"},
		{"Config label", "Config:"},
		{"Config key", "sandbox.unix_sockets.enabled"},
		{"Config value", "= true"},
		{"Error label", "Error:"},
		{"Error message", "test error message"},
		{"Fix label", "To fix:"},
		{"Suggestion", "sandbox.unix_sockets.enabled: false"},
		{"Alternative", "upgrade to a kernel"},
	}

	for _, part := range expectedParts {
		if !strings.Contains(errStr, part.value) {
			t.Errorf("error format missing %s (%q), got:\n%s", part.name, part.value, errStr)
		}
	}
}

// Table-driven test for single feature checks
func TestCheckAll_SingleFeatureChecks(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func()
		config        *config.Config
		wantErr       bool
		errContains   []string
		cleanupMocks  func()
	}{
		{
			name: "unix_sockets enabled, seccomp available",
			setupMocks: func() {
				checkSeccompUserNotify = func() CheckResult {
					return CheckResult{Feature: "seccomp-user-notify", Available: true}
				}
				checkWrapperBinary = func(string) CheckResult {
					return CheckResult{Feature: "seccomp-wrapper-binary", Available: true}
				}
			},
			config: func() *config.Config {
				enabled := true
				return &config.Config{
					Sandbox: config.SandboxConfig{
						UnixSockets: config.SandboxUnixSocketsConfig{Enabled: &enabled},
					},
				}
			}(),
			wantErr: false,
		},
		{
			name: "seccomp.enabled triggers check",
			setupMocks: func() {
				checkSeccompUserNotify = func() CheckResult {
					return CheckResult{
						Feature:   "seccomp-user-notify",
						Available: false,
						Error:     errors.New("unavailable"),
					}
				}
			},
			config: &config.Config{
				Sandbox: config.SandboxConfig{
					Seccomp: config.SandboxSeccompConfig{Enabled: true},
				},
			},
			wantErr:     true,
			errContains: []string{"seccomp-user-notify", "sandbox.seccomp.enabled"},
		},
		{
			name: "cgroups enabled triggers both ptrace and cgroups v2 checks",
			setupMocks: func() {
				checkCgroupsV2 = func() CheckResult {
					return CheckResult{Feature: "cgroups-v2", Available: true}
				}
				checkPtrace = func() CheckResult {
					return CheckResult{Feature: "ptrace", Available: true}
				}
			},
			config: &config.Config{
				Sandbox: config.SandboxConfig{
					Cgroups: config.SandboxCgroupsConfig{Enabled: true},
				},
			},
			wantErr: false,
		},
		{
			name: "ebpf enabled triggers ebpf check",
			setupMocks: func() {
				checkeBPF = func() CheckResult {
					return CheckResult{Feature: "ebpf", Available: true}
				}
			},
			config: &config.Config{
				Sandbox: config.SandboxConfig{
					Network: config.SandboxNetworkConfig{
						EBPF: config.SandboxEBPFConfig{Enabled: true},
					},
				},
			},
			wantErr: false,
		},
	}

	// Save originals
	origSeccomp := checkSeccompUserNotify
	origPtrace := checkPtrace
	origCgroups := checkCgroupsV2
	origEBPF := checkeBPF
	origBinary := checkWrapperBinary

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to originals before each test
			checkSeccompUserNotify = origSeccomp
			checkPtrace = origPtrace
			checkCgroupsV2 = origCgroups
			checkeBPF = origEBPF
			checkWrapperBinary = origBinary

			// Apply test-specific mocks
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			err := CheckAll(tt.config)

			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}

			if err != nil {
				errStr := err.Error()
				for _, s := range tt.errContains {
					if !strings.Contains(errStr, s) {
						t.Errorf("error should contain %q, got: %v", s, err)
					}
				}
			}
		})
	}

	// Restore originals after all tests
	checkSeccompUserNotify = origSeccomp
	checkPtrace = origPtrace
	checkCgroupsV2 = origCgroups
	checkeBPF = origEBPF
	checkWrapperBinary = origBinary
}

func TestCheckAll_WrapperBinary_UnixSocketsEnabled(t *testing.T) {
	// Save and restore originals
	origSeccomp := checkSeccompUserNotify
	origBinary := checkWrapperBinary
	defer func() {
		checkSeccompUserNotify = origSeccomp
		checkWrapperBinary = origBinary
	}()

	// Mock seccomp to pass
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{Feature: "seccomp-user-notify", Available: true}
	}

	// Mock binary check to fail
	checkWrapperBinary = func(path string) CheckResult {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: false,
			Error:     errors.New("wrapper binary \"agentsh-unixwrap\" not found in PATH"),
		}
	}

	enabled := true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled: &enabled,
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when wrapper binary not found")
	}

	errStr := err.Error()

	// Verify error message
	if !strings.Contains(errStr, "seccomp-wrapper-binary") {
		t.Errorf("error should mention feature, got: %v", err)
	}
	if !strings.Contains(errStr, "sandbox.unix_sockets.enabled") {
		t.Errorf("error should mention config key, got: %v", err)
	}
	if !strings.Contains(errStr, "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
	if !strings.Contains(errStr, "Install the agentsh-unixwrap binary") {
		t.Errorf("error should suggest installing binary, got: %v", err)
	}
	// Should NOT suggest kernel upgrade for binary issues
	if strings.Contains(errStr, "upgrade to a kernel") {
		t.Errorf("error should NOT suggest kernel upgrade for binary issue, got: %v", err)
	}
}

func TestCheckAll_WrapperBinary_ExecveEnabled(t *testing.T) {
	// Save and restore originals
	origBinary := checkWrapperBinary
	defer func() {
		checkWrapperBinary = origBinary
	}()

	// Mock binary check to fail
	checkWrapperBinary = func(path string) CheckResult {
		return CheckResult{
			Feature:   "seccomp-wrapper-binary",
			Available: false,
			Error:     errors.New("wrapper binary \"agentsh-unixwrap\" not found in PATH"),
		}
	}

	// Enable only execve (not unix_sockets)
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			Seccomp: config.SandboxSeccompConfig{
				Execve: config.ExecveConfig{
					Enabled: true,
				},
			},
		},
	}

	err := CheckAll(cfg)
	if err == nil {
		t.Fatal("expected error when wrapper binary not found with execve enabled")
	}

	errStr := err.Error()

	// Verify config key is correct for execve
	if !strings.Contains(errStr, "sandbox.seccomp.execve.enabled") {
		t.Errorf("error should mention sandbox.seccomp.execve.enabled, got: %v", err)
	}
}

func TestCheckAll_WrapperBinary_CustomPath(t *testing.T) {
	// Save and restore originals
	origSeccomp := checkSeccompUserNotify
	origBinary := checkWrapperBinary
	defer func() {
		checkSeccompUserNotify = origSeccomp
		checkWrapperBinary = origBinary
	}()

	// Mock seccomp to pass
	checkSeccompUserNotify = func() CheckResult {
		return CheckResult{Feature: "seccomp-user-notify", Available: true}
	}

	// Track what path was passed to the check
	var checkedPath string
	checkWrapperBinary = func(path string) CheckResult {
		checkedPath = path
		return CheckResult{Feature: "seccomp-wrapper-binary", Available: true}
	}

	enabled := true
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			UnixSockets: config.SandboxUnixSocketsConfig{
				Enabled:    &enabled,
				WrapperBin: "/custom/path/to/wrapper",
			},
		},
	}

	err := CheckAll(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if checkedPath != "/custom/path/to/wrapper" {
		t.Errorf("expected custom path to be checked, got: %q", checkedPath)
	}
}
