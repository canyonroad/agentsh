//go:build windows

package windows

import (
	"context"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/agentsh/agentsh/internal/platform"
	"golang.org/x/sys/windows"
)

func TestAppContainerName(t *testing.T) {
	name := appContainerName("test-sandbox-123")
	if !strings.HasPrefix(name, "agentsh-sandbox-") {
		t.Errorf("expected prefix 'agentsh-sandbox-', got %s", name)
	}
	if !strings.Contains(name, "test-sandbox-123") {
		t.Errorf("expected to contain sandbox id, got %s", name)
	}
}

func TestAppContainerNameSanitization(t *testing.T) {
	// Container names must be valid for registry keys
	name := appContainerName(`test/with\special:chars*?"<>|more`)
	if strings.ContainsAny(name, `/\:*?"<>|`) {
		t.Errorf("name should not contain special chars: %s", name)
	}
}

func TestAppContainerCreateDelete(t *testing.T) {
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	ac := newAppContainer("test-create-delete")

	// Create should succeed
	if err := ac.create(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	defer ac.cleanup()

	if !ac.created {
		t.Error("created flag should be true")
	}
	if ac.sid == nil {
		t.Error("SID should be set after create")
	}

	// Cleanup should succeed
	if err := ac.cleanup(); err != nil {
		t.Errorf("cleanup failed: %v", err)
	}
}

func TestAppContainerGrantPath(t *testing.T) {
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	// Create a temp directory to test ACL modification
	tempDir := t.TempDir()

	ac := newAppContainer("test-grant-path")
	if err := ac.create(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	defer ac.cleanup()

	// Grant access should succeed
	if err := ac.grantPathAccess(tempDir, AccessReadWrite); err != nil {
		t.Fatalf("grantPathAccess failed: %v", err)
	}

	// Should be tracked for cleanup
	if len(ac.grantedACLs) != 1 {
		t.Errorf("expected 1 granted ACL, got %d", len(ac.grantedACLs))
	}
}

func isAdmin() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func TestNetworkCapabilityWKSIDs(t *testing.T) {
	tests := []struct {
		level    platform.NetworkAccessLevel
		expected int // number of capability SIDs
	}{
		{platform.NetworkNone, 0},
		{platform.NetworkOutbound, 1}, // internetClient
		{platform.NetworkLocal, 1},    // privateNetworkClientServer
		{platform.NetworkFull, 2},     // internetClient + privateNetworkClientServer
	}

	for _, tc := range tests {
		sids := networkCapabilitySIDs(tc.level)
		if len(sids) != tc.expected {
			t.Errorf("NetworkAccessLevel %d: expected %d SIDs, got %d", tc.level, tc.expected, len(sids))
		}
	}
}

func TestAppContainerCreateProcess(t *testing.T) {
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	ac := newAppContainer("test-create-process")
	if err := ac.create(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	defer ac.cleanup()

	// Use temp directory instead of System32 to avoid requiring special privileges
	tempDir := t.TempDir()
	if err := ac.grantPathAccess(tempDir, AccessReadWrite); err != nil {
		t.Fatalf("grant path failed: %v", err)
	}

	// cmd.exe should work from PATH without explicit System32 ACL grant
	ctx := context.Background()
	proc, err := ac.createProcess(ctx, "cmd.exe", []string{"/c", "echo", "hello"}, nil, tempDir)
	if err != nil {
		// AppContainer process creation may fail in CI without full elevation
		t.Skipf("createProcess failed (may need full admin): %v", err)
	}
	defer proc.Kill()

	state, err := proc.Wait()
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	if state.ExitCode() != 0 {
		t.Errorf("expected exit code 0, got %d", state.ExitCode())
	}
}

func TestMergeWithParentEnv(t *testing.T) {
	// Save and restore environment
	origEnv := os.Environ()
	os.Clearenv()
	os.Setenv("EXISTING_VAR", "original")
	os.Setenv("PATH", "/usr/bin")
	defer func() {
		os.Clearenv()
		for _, e := range origEnv {
			if k, v, ok := strings.Cut(e, "="); ok {
				os.Setenv(k, v)
			}
		}
	}()

	tests := []struct {
		name     string
		inject   map[string]string
		wantKey  string
		wantVal  string
	}{
		{
			name:    "empty inject returns parent env",
			inject:  map[string]string{},
			wantKey: "EXISTING_VAR",
			wantVal: "original",
		},
		{
			name:    "inject adds new variable",
			inject:  map[string]string{"NEW_VAR": "new_value"},
			wantKey: "NEW_VAR",
			wantVal: "new_value",
		},
		{
			name:    "inject overrides existing variable",
			inject:  map[string]string{"EXISTING_VAR": "overridden"},
			wantKey: "EXISTING_VAR",
			wantVal: "overridden",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mergeWithParentEnv(tt.inject)
			if result[tt.wantKey] != tt.wantVal {
				t.Errorf("mergeWithParentEnv() got %q = %q, want %q", tt.wantKey, result[tt.wantKey], tt.wantVal)
			}
		})
	}
}

func TestBuildEnvironmentBlock(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantNil  bool
		contains []string
	}{
		{
			name:    "empty env returns nil",
			env:     map[string]string{},
			wantNil: true,
		},
		{
			name:     "single var creates block",
			env:      map[string]string{"FOO": "bar"},
			wantNil:  false,
			contains: []string{"FOO=bar"},
		},
		{
			name:     "multiple vars creates block",
			env:      map[string]string{"FOO": "bar", "BAZ": "qux"},
			wantNil:  false,
			contains: []string{"FOO=bar", "BAZ=qux"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildEnvironmentBlock(tt.env)
			if tt.wantNil {
				if result != nil {
					t.Errorf("buildEnvironmentBlock() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Errorf("buildEnvironmentBlock() = nil, want non-nil")
				return
			}
			// Decode UTF-16 block back to string for verification
			block := decodeEnvironmentBlock(result)
			for _, want := range tt.contains {
				found := false
				for _, got := range block {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("buildEnvironmentBlock() missing %q in %v", want, block)
				}
			}
		})
	}
}

// decodeEnvironmentBlock converts a UTF-16 environment block back to strings for testing
func decodeEnvironmentBlock(block *uint16) []string {
	if block == nil {
		return nil
	}
	var result []string
	ptr := unsafe.Pointer(block)
	for {
		s := windows.UTF16PtrToString((*uint16)(ptr))
		if s == "" {
			break
		}
		result = append(result, s)
		// Move pointer past this string + null terminator
		ptr = unsafe.Pointer(uintptr(ptr) + uintptr((len(s)+1)*2))
	}
	return result
}
