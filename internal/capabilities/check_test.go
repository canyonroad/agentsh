//go:build linux

package capabilities

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/stretchr/testify/assert"
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

func TestProbeEBPF(t *testing.T) {
	result := probeEBPF()
	assert.NotEmpty(t, result.Detail)
}

// TestProbeEBPFCanary is a regression test for #196. The original probe
// used a single BPF_EXIT instruction with uninitialized r0, which the BPF
// verifier rejects with EACCES even on systems where eBPF is fully
// functional. It also used progType=13 with a comment claiming
// BPF_PROG_TYPE_CGROUP_SKB, but value 13 is BPF_PROG_TYPE_SOCK_OPS and the
// real netmonitor loads CGROUP_SOCK_ADDR programs (cgroup/connect*,
// cgroup/sendmsg*), not skb programs. This test locks in the corrected
// canary so the bug cannot be reintroduced.
func TestProbeEBPFCanary(t *testing.T) {
	// BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18 — matches the program family the
	// real netmonitor attaches (cgroup/connect*, cgroup/sendmsg*).
	assert.Equal(t, uint32(18), probeEBPFCanaryProgType,
		"canary must use BPF_PROG_TYPE_CGROUP_SOCK_ADDR (18), not SOCK_OPS (13), CGROUP_SKB (8), or SOCKET_FILTER (1)")

	// expected_attach_type is required for CGROUP_SOCK_ADDR — without it
	// the kernel rejects the load with EINVAL. BPF_CGROUP_INET4_CONNECT is
	// one of the valid attach types the real netmonitor uses.
	assert.Equal(t, uint32(10), probeEBPFCanaryExpectedAttachType,
		"canary must set expected_attach_type to BPF_CGROUP_INET4_CONNECT (10)")

	// Two 8-byte instructions: r0=0, exit.
	assert.Equal(t, uint32(2), probeEBPFCanaryInsnCnt,
		"canary must be 2 instructions (r0=0; exit) — a lone BPF_EXIT is rejected by the verifier")
	assert.Len(t, probeEBPFCanaryInsns, 16,
		"canary must be 16 bytes (2 instructions * 8 bytes each)")

	// First instruction: BPF_ALU64 | BPF_MOV | BPF_K, dst=r0, imm=0 → opcode 0xb7.
	assert.Equal(t, byte(0xb7), probeEBPFCanaryInsns[0],
		"first instruction opcode must be 0xb7 (r0 = 0)")

	// Second instruction: BPF_JMP | BPF_EXIT → opcode 0x95.
	assert.Equal(t, byte(0x95), probeEBPFCanaryInsns[8],
		"second instruction opcode must be 0x95 (exit)")

	// Lock in the bpf_attr layout so a future truncation or field reorder
	// is caught even on hosts where eBPF support is unavailable and the
	// probeEBPF() call below is short-circuited by ebpf.CheckSupport. The
	// kernel reads attr_size bytes from userspace; for CGROUP_SOCK_ADDR the
	// struct MUST extend through expected_attach_type (offset 68, total
	// size 72). Truncating back to the 48-byte variant reintroduces the
	// EINVAL failure mode described in the commit message.
	assert.Equal(t, uintptr(72), unsafe.Sizeof(bpfProgLoadAttr{}),
		"bpfProgLoadAttr must be 72 bytes — the kernel rejects CGROUP_SOCK_ADDR loads with attr_size < expected_attach_type offset+4")
	assert.Equal(t, uintptr(68), unsafe.Offsetof(bpfProgLoadAttr{}.expectedAttachType),
		"expectedAttachType must be at offset 68 — do not reorder fields or add fields before it")

	// On systems where the probe succeeds, the detail must identify the
	// canary program family. probeEBPF gates the canary behind
	// ebpf.CheckSupport, so on environments where the check fails,
	// Available is false and the detail is the reason from CheckSupport
	// rather than "cgroup_sock_addr".
	result := probeEBPF()
	if result.Available {
		assert.Equal(t, "cgroup_sock_addr", result.Detail)
	}
}

func TestProbeCgroupsV2(t *testing.T) {
	result := probeCgroupsV2()
	assert.NotEmpty(t, result.Detail)
}

func TestProbePIDNamespace(t *testing.T) {
	result := probePIDNamespace()
	assert.NotEmpty(t, result.Detail)
}

func TestProbeCapabilityDrop(t *testing.T) {
	result := probeCapabilityDrop()
	assert.NotEmpty(t, result.Detail)
}
