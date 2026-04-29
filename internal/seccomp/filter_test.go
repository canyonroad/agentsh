//go:build linux && cgo

package seccomp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildFilterConfig(t *testing.T) {
	cfg := FilterConfig{
		UnixSocketEnabled: true,
		BlockedSyscalls:   []string{"ptrace", "mount"},
	}

	// Just test that we can build the config without error
	require.NotEmpty(t, cfg.BlockedSyscalls)
	require.True(t, cfg.UnixSocketEnabled)
}

func TestResolveSyscallNumbers(t *testing.T) {
	tests := []struct {
		name string
		want bool // should resolve successfully
	}{
		{"ptrace", true},
		{"mount", true},
		{"process_vm_readv", true},
		{"not_a_real_syscall", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nr, err := ResolveSyscall(tc.name)
			if tc.want {
				require.NoError(t, err)
				require.GreaterOrEqual(t, nr, 0)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestResolveSyscalls(t *testing.T) {
	t.Run("empty input returns empty slices", func(t *testing.T) {
		numbers, skipped := ResolveSyscalls(nil)
		require.Empty(t, numbers)
		require.Empty(t, skipped)

		numbers, skipped = ResolveSyscalls([]string{})
		require.Empty(t, numbers)
		require.Empty(t, skipped)
	})

	t.Run("all valid syscalls are resolved", func(t *testing.T) {
		names := []string{"read", "write", "open"}
		numbers, skipped := ResolveSyscalls(names)
		require.Len(t, numbers, 3)
		require.Empty(t, skipped)
		for _, nr := range numbers {
			require.GreaterOrEqual(t, nr, 0)
		}
	})

	t.Run("invalid syscalls are skipped", func(t *testing.T) {
		names := []string{"not_a_syscall", "also_fake"}
		numbers, skipped := ResolveSyscalls(names)
		require.Empty(t, numbers)
		require.Len(t, skipped, 2)
		require.Contains(t, skipped, "not_a_syscall")
		require.Contains(t, skipped, "also_fake")
	})

	t.Run("mixed valid and invalid input", func(t *testing.T) {
		names := []string{"read", "not_real", "write", "fake_syscall"}
		numbers, skipped := ResolveSyscalls(names)
		require.Len(t, numbers, 2)
		require.Len(t, skipped, 2)
		require.Contains(t, skipped, "not_real")
		require.Contains(t, skipped, "fake_syscall")
	})
}

func TestParseOnBlock(t *testing.T) {
	tests := []struct {
		input    string
		expected OnBlockAction
		ok       bool
	}{
		{"", OnBlockErrno, true},
		{"errno", OnBlockErrno, true},
		{"kill", OnBlockKill, true},
		{"log", OnBlockLog, true},
		{"log_and_kill", OnBlockLogAndKill, true},
		{"banana", OnBlockErrno, false},
		{"KILL", OnBlockErrno, false}, // case sensitive
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := ParseOnBlock(tc.input)
			require.Equal(t, tc.expected, got)
			require.Equal(t, tc.ok, ok)
		})
	}
}

func TestFilterConfigFromYAML(t *testing.T) {
	cfg := FilterConfigFromYAML(true, []string{"ptrace"}, "log_and_kill", nil)
	require.True(t, cfg.UnixSocketEnabled)
	require.Equal(t, []string{"ptrace"}, cfg.BlockedSyscalls)
	require.Equal(t, OnBlockLogAndKill, cfg.OnBlock)

	// Unknown string degrades to errno
	cfgBad := FilterConfigFromYAML(false, nil, "nope", nil)
	require.Equal(t, OnBlockErrno, cfgBad.OnBlock)
}

func TestFilterConfig_IncludesBlockedFamilies(t *testing.T) {
	cfg := FilterConfig{
		UnixSocketEnabled: false,
		BlockedSyscalls:   nil,
		BlockedFamilies: []BlockedFamily{
			{Family: 38, Action: OnBlockErrno, Name: "AF_ALG"},
		},
		OnBlock: OnBlockErrno,
	}
	if len(cfg.BlockedFamilies) != 1 {
		t.Fatalf("expected 1 family, got %d", len(cfg.BlockedFamilies))
	}
	if cfg.BlockedFamilies[0].Name != "AF_ALG" {
		t.Errorf("name=%q want AF_ALG", cfg.BlockedFamilies[0].Name)
	}
}

func TestFilterConfigFromYAML_PassesFamilies(t *testing.T) {
	families := []BlockedFamily{
		{Family: 38, Action: OnBlockErrno, Name: "AF_ALG"},
	}
	cfg := FilterConfigFromYAML(true, []string{"ptrace"}, "errno", families)
	if len(cfg.BlockedFamilies) != 1 || cfg.BlockedFamilies[0].Family != 38 {
		t.Errorf("FilterConfigFromYAML did not pass families through: %+v", cfg.BlockedFamilies)
	}
}
