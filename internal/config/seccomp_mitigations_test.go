package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"github.com/stretchr/testify/require"
)

func TestEffectiveSeccompRules_BuiltInDirtyFrag(t *testing.T) {
	eff, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
	})
	require.NoError(t, err)
	require.Len(t, eff.LoadedMitigations, 1)
	require.Equal(t, "dirtyfrag-conservative", eff.LoadedMitigations[0].ID)
	require.Equal(t, "builtin", eff.LoadedMitigations[0].Source)
	require.NotEmpty(t, eff.LoadedMitigations[0].Checksum)
	require.Len(t, eff.SocketRules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", eff.SocketRules[0].Name)
	require.Equal(t, "AF_RXRPC", eff.SocketRules[0].Family)
	require.Equal(t, "log_and_kill", eff.SocketRules[0].Action)
	require.Equal(t, "dirtyfrag-conservative-xfrm", eff.SocketRules[1].Name)
	require.Equal(t, "AF_NETLINK", eff.SocketRules[1].Family)
	require.Equal(t, "NETLINK_XFRM", eff.SocketRules[1].Protocol)
	require.Equal(t, "log_and_kill", eff.SocketRules[1].Action)
}

func TestEffectiveSeccompRules_RejectsBuiltInExternalDuplicateBeforeParsing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dirtyfrag-conservative.yaml"), []byte("not: active\n"), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "exists as both built-in and external")
}

func TestResolveSocketRules_BuiltInDirtyFrag(t *testing.T) {
	rules, err := ResolveSocketRules(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
	})
	require.NoError(t, err)
	require.Len(t, rules, 2)

	rxrpcFamily, _, ok := seccomp.ParseFamily("AF_RXRPC")
	require.True(t, ok)
	netlinkFamily, _, ok := seccomp.ParseFamily("AF_NETLINK")
	require.True(t, ok)
	xfrmProtocol, _, ok := seccomp.ParseSocketProtocol("NETLINK_XFRM")
	require.True(t, ok)

	require.Equal(t, rxrpcFamily, rules[0].Family)
	require.Equal(t, seccomp.OnBlockLogAndKill, rules[0].Action)
	require.Equal(t, netlinkFamily, rules[1].Family)
	require.NotNil(t, rules[1].Protocol)
	require.Equal(t, xfrmProtocol, *rules[1].Protocol)
	require.Equal(t, seccomp.OnBlockLogAndKill, rules[1].Action)
}

func TestEffectiveSeccompRules_RejectsUnknownMitigationSet(t *testing.T) {
	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `mitigation_sets[0]`)
	require.Contains(t, err.Error(), "dirtyfrag")
}

func TestEffectiveSeccompRules_RejectsDuplicateRequestedMitigationSet(t *testing.T) {
	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets:    []string{"dirtyfrag-conservative"},
		HardeningProfiles: []string{"dirtyfrag-conservative"},
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "duplicate mitigation set"), err.Error())
}

func TestEffectiveSeccompRules_ExternalMitigation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local-xfrm.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
version: 1
id: local-xfrm
seccomp:
  socket_rules:
    - name: local-xfrm
      family: AF_NETLINK
      protocol: NETLINK_XFRM
      action: log
`), 0o600))

	eff, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"local-xfrm"},
		MitigationDirs: []string{dir},
	})
	require.NoError(t, err)
	require.Len(t, eff.SocketRules, 1)
	require.Equal(t, "local-xfrm", eff.SocketRules[0].Name)
	require.Len(t, eff.LoadedMitigations, 1)
	require.Equal(t, "external", eff.LoadedMitigations[0].Source)
	require.Equal(t, path, eff.LoadedMitigations[0].Path)
}

func TestEffectiveSeccompRules_RejectsInvalidMitigationID(t *testing.T) {
	for _, id := range []string{"../dirtyfrag", "/dirtyfrag", "DirtyFrag", ""} {
		t.Run(id, func(t *testing.T) {
			_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
				MitigationSets: []string{id},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid mitigation set id")
		})
	}
}

func TestEffectiveSeccompRules_RejectsUnknownYAMLFields(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(`
version: 1
id: bad
unexpected: true
seccomp:
  socket_rules:
    - name: bad
      family: AF_RXRPC
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"bad"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "field unexpected not found")
}

func TestEffectiveSeccompRules_RejectsMismatchedYAMLID(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wanted.yaml"), []byte(`
version: 1
id: other
seccomp:
  socket_rules:
    - name: other
      family: AF_RXRPC
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"wanted"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `id "other" does not match requested id "wanted"`)
}

func TestEffectiveSeccompRules_RejectsEmptyMitigation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty.yaml"), []byte(`
version: 1
id: empty
seccomp: {}
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"empty"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty mitigations are not allowed")
}

func TestEffectiveSeccompRules_RejectsBuiltInExternalDuplicate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dirtyfrag-conservative.yaml"), []byte(`
version: 1
id: dirtyfrag-conservative
seccomp:
  socket_rules:
    - name: replacement
      family: AF_RXRPC
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "exists as both built-in and external")
}

func TestEffectiveSeccompRules_RejectsWorldWritableExternalFileOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode bits are not portable to Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "unsafe.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
version: 1
id: unsafe
seccomp:
  socket_rules:
    - name: unsafe
      family: AF_RXRPC
`), 0o666))
	require.NoError(t, os.Chmod(path, 0o666))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"unsafe"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "world-writable")
}

func TestEffectiveSeccompRules_RejectsTrailingYAMLDocument(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "multi.yaml"), []byte(`
version: 1
id: multi
seccomp:
  socket_rules:
    - name: multi
      family: AF_RXRPC
---
version: 1
id: ignored
seccomp:
  socket_rules:
    - name: ignored
      family: AF_NETLINK
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"multi"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "multiple YAML documents")
}

func TestEffectiveSeccompRules_RejectsBadMitigationVersion(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad-version.yaml"), []byte(`
version: 2
id: bad-version
seccomp:
  socket_rules:
    - name: bad-version
      family: AF_RXRPC
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"bad-version"},
		MitigationDirs: []string{dir},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "version must be 1")
}
