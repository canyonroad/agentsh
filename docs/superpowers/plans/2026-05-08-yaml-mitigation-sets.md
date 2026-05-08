# YAML Mitigation Sets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded advisory profiles with YAML-backed mitigation sets that load only when selected and expand into existing seccomp primitives.

**Architecture:** Add a config-layer mitigation resolver that loads embedded built-in YAML files and optional external YAML files by requested ID. The resolver produces effective seccomp config slices, and existing seccomp, ptrace, wrapper, and notify code consume those effective slices instead of hardcoded `hardening_profiles`.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, `go:embed`, seccomp/libseccomp, ptrace fallback, platform-specific build tags.

---

## File Structure

- Create `internal/config/mitigations/dirtyfrag-conservative.yaml`
  - Built-in Dirty Frag mitigation data embedded into the binary.
- Create `internal/config/seccomp_mitigations.go`
  - Mitigation YAML schema, embedded-file lookup, external-file lookup, strict YAML decode, effective-rule merge helpers, load metadata.
- Create `internal/config/seccomp_mitigations_unix.go`
  - Unix permission checks for external mitigation directories and files.
- Create `internal/config/seccomp_mitigations_other.go`
  - Non-Unix permission-check stub.
- Create `internal/config/seccomp_mitigations_test.go`
  - Resolver, schema, duplicate, external-dir, and syscall merge tests.
- Modify `internal/config/config.go`
  - Add `mitigation_sets` and `mitigation_dirs`, keep `hardening_profiles` as deprecated alias, validate effective mitigation-expanded config.
- Modify `internal/config/seccomp_socket_rules.go`
  - Remove hardcoded `dirtyfrag-conservative` switch; resolve through mitigation loader.
- Modify `internal/config/seccomp_socket_rules_test.go`
  - Rename profile tests to mitigation-set tests and keep one alias coverage test.
- Modify `internal/api/seccomp_wrapper_config.go`
  - Forward mitigation-expanded syscall blocks, socket families, and socket rules to the wrapper.
- Modify `internal/api/blocklist_config_linux.go`
  - Build notify dispatch maps from mitigation-expanded rules.
- Modify `internal/api/wrap.go`
  - Gate user-notify startup from mitigation-expanded syscall/family/socket tuple rules.
- Modify `internal/api/app_ptrace_linux.go`
  - Build ptrace family and socket tuple checkers from mitigation-expanded rules.
- Modify focused API tests in `internal/api/*test.go`
  - Update `hardening_profiles` expectations to `mitigation_sets`; add effective-rule wiring coverage.
- Modify `docs/seccomp.md` and `config.yml`
  - Present `mitigation_sets` and `mitigation_dirs`; stop presenting `hardening_profiles` as the preferred interface.

## Task 1: Config Surface

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/seccomp_socket_rules_test.go`

- [ ] **Step 1: Write failing YAML parse tests**

Add these tests to `internal/config/seccomp_socket_rules_test.go`:

```go
func TestSandboxSeccompMitigationSets_ParseYAML(t *testing.T) {
	data := []byte(`
sandbox:
  seccomp:
    mitigation_sets:
      - dirtyfrag-conservative
    mitigation_dirs:
      - /etc/agentsh/mitigations
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.Equal(t, []string{"dirtyfrag-conservative"}, cfg.Sandbox.Seccomp.MitigationSets)
	require.Equal(t, []string{"/etc/agentsh/mitigations"}, cfg.Sandbox.Seccomp.MitigationDirs)
}

func TestSandboxSeccompHardeningProfiles_DeprecatedAliasParseYAML(t *testing.T) {
	data := []byte(`
sandbox:
  seccomp:
    hardening_profiles:
      - dirtyfrag-conservative
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.Equal(t, []string{"dirtyfrag-conservative"}, cfg.Sandbox.Seccomp.HardeningProfiles)
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/config -run 'MitigationSets|HardeningProfiles' -count=1
```

Expected: FAIL because `MitigationSets` and `MitigationDirs` do not exist on `SandboxSeccompConfig`.

- [ ] **Step 3: Add config fields**

In `internal/config/config.go`, update `SandboxSeccompConfig`:

```go
	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families"`
	SocketRules           []SandboxSeccompSocketRuleConfig   `yaml:"socket_rules"`
	MitigationSets        []string                           `yaml:"mitigation_sets"`
	MitigationDirs        []string                           `yaml:"mitigation_dirs"`
	// HardeningProfiles is a deprecated alias for MitigationSets. It exists
	// only so config files written against the Dirty Frag feature branch fail
	// less abruptly while the public name changes.
	HardeningProfiles []string `yaml:"hardening_profiles"`
```

- [ ] **Step 4: Run tests to verify pass**

Run:

```bash
go test ./internal/config -run 'MitigationSets|HardeningProfiles' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/seccomp_socket_rules_test.go
git commit -m "config: add mitigation set fields"
```

## Task 2: Built-In Mitigation YAML Loader

**Files:**
- Create: `internal/config/mitigations/dirtyfrag-conservative.yaml`
- Create: `internal/config/seccomp_mitigations.go`
- Create: `internal/config/seccomp_mitigations_test.go`
- Modify: `internal/config/seccomp_socket_rules.go`

- [ ] **Step 1: Add built-in Dirty Frag YAML**

Create `internal/config/mitigations/dirtyfrag-conservative.yaml`:

```yaml
version: 1
id: dirtyfrag-conservative
title: Dirty Frag conservative mitigation
references:
  - https://www.openwall.com/lists/oss-security/2026/05/07/8

seccomp:
  socket_rules:
    - name: dirtyfrag-conservative-rxrpc
      family: AF_RXRPC
      action: log_and_kill
    - name: dirtyfrag-conservative-xfrm
      family: AF_NETLINK
      protocol: NETLINK_XFRM
      action: log_and_kill
```

- [ ] **Step 2: Write failing built-in resolver tests**

Create `internal/config/seccomp_mitigations_test.go` with:

```go
package config

import (
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
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
go test ./internal/config -run 'EffectiveSeccompRules|ResolveSocketRules_BuiltInDirtyFrag' -count=1
```

Expected: FAIL because the mitigation resolver does not exist.

- [ ] **Step 4: Implement embedded mitigation loader**

Create `internal/config/seccomp_mitigations.go`:

```go
package config

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed mitigations/*.yaml
var builtinMitigationFS embed.FS

var mitigationIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

type EffectiveSeccompRules struct {
	SocketRules           []SandboxSeccompSocketRuleConfig
	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig
	SyscallBlock          []string
	SyscallOnBlock        string
	LoadedMitigations    []MitigationLoadInfo
}

type MitigationLoadInfo struct {
	ID                    string
	Source                string
	Path                  string
	Checksum              string
	SocketRules           int
	BlockedSocketFamilies int
	Syscalls              int
}

type mitigationDocument struct {
	Version    int                `yaml:"version"`
	ID         string             `yaml:"id"`
	Title      string             `yaml:"title,omitempty"`
	References []string           `yaml:"references,omitempty"`
	Seccomp    mitigationSeccomp  `yaml:"seccomp"`
}

type mitigationSeccomp struct {
	SocketRules           []SandboxSeccompSocketRuleConfig   `yaml:"socket_rules"`
	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families"`
	Syscalls              mitigationSyscalls                 `yaml:"syscalls"`
}

type mitigationSyscalls struct {
	Block   []string `yaml:"block"`
	OnBlock string   `yaml:"on_block"`
}

func EffectiveSeccompRulesForConfig(in SandboxSeccompConfig) (EffectiveSeccompRules, error) {
	out := EffectiveSeccompRules{
		SocketRules:           append([]SandboxSeccompSocketRuleConfig(nil), in.SocketRules...),
		BlockedSocketFamilies: append([]SandboxSeccompSocketFamilyConfig(nil), in.BlockedSocketFamilies...),
		SyscallBlock:          append([]string(nil), in.Syscalls.Block...),
		SyscallOnBlock:        in.Syscalls.OnBlock,
	}
	if out.SyscallOnBlock == "" {
		out.SyscallOnBlock = "errno"
	}

	ids, err := requestedMitigationSetIDs(in)
	if err != nil {
		return EffectiveSeccompRules{}, err
	}
	for i, id := range ids {
		doc, info, err := loadMitigationSet(id, in.MitigationDirs)
		if err != nil {
			return EffectiveSeccompRules{}, fmt.Errorf("mitigation_sets[%d]: %w", i, err)
		}
		if doc.Seccomp.Syscalls.OnBlock != "" && doc.Seccomp.Syscalls.OnBlock != out.SyscallOnBlock {
			return EffectiveSeccompRules{}, fmt.Errorf("mitigation_sets[%d] %q: seccomp.syscalls.on_block %q conflicts with effective sandbox.seccomp.syscalls.on_block %q",
				i, id, doc.Seccomp.Syscalls.OnBlock, out.SyscallOnBlock)
		}
		out.SocketRules = append(out.SocketRules, doc.Seccomp.SocketRules...)
		out.BlockedSocketFamilies = append(out.BlockedSocketFamilies, doc.Seccomp.BlockedSocketFamilies...)
		out.SyscallBlock = append(out.SyscallBlock, doc.Seccomp.Syscalls.Block...)
		out.LoadedMitigations = append(out.LoadedMitigations, info)
	}
	return out, nil
}

func requestedMitigationSetIDs(in SandboxSeccompConfig) ([]string, error) {
	ids := make([]string, 0, len(in.MitigationSets)+len(in.HardeningProfiles))
	seen := map[string]struct{}{}
	for _, source := range []struct {
		field string
		vals  []string
	}{
		{field: "mitigation_sets", vals: in.MitigationSets},
		{field: "hardening_profiles", vals: in.HardeningProfiles},
	} {
		for i, id := range source.vals {
			if !mitigationIDPattern.MatchString(id) {
				return nil, fmt.Errorf("%s[%d]: invalid mitigation set id %q", source.field, i, id)
			}
			if _, ok := seen[id]; ok {
				return nil, fmt.Errorf("duplicate mitigation set %q", id)
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func loadMitigationSet(id string, dirs []string) (mitigationDocument, MitigationLoadInfo, error) {
	builtinData, builtinFound, err := readBuiltinMitigation(id)
	if err != nil {
		return mitigationDocument{}, MitigationLoadInfo{}, err
	}
	externalData, externalPath, externalFound, err := readExternalMitigation(id, dirs)
	if err != nil {
		return mitigationDocument{}, MitigationLoadInfo{}, err
	}
	if builtinFound && externalFound {
		return mitigationDocument{}, MitigationLoadInfo{}, fmt.Errorf("%q exists as both built-in and external mitigation %q", id, externalPath)
	}
	if !builtinFound && !externalFound {
		return mitigationDocument{}, MitigationLoadInfo{}, fmt.Errorf("unknown mitigation set %q", id)
	}

	source := "builtin"
	path := mitigationFSPath(id)
	data := builtinData
	if externalFound {
		source = "external"
		path = externalPath
		data = externalData
	}
	doc, err := decodeMitigation(id, data, path)
	if err != nil {
		return mitigationDocument{}, MitigationLoadInfo{}, err
	}
	sum := sha256.Sum256(data)
	info := MitigationLoadInfo{
		ID:                    id,
		Source:                source,
		Path:                  path,
		Checksum:              "sha256:" + hex.EncodeToString(sum[:]),
		SocketRules:           len(doc.Seccomp.SocketRules),
		BlockedSocketFamilies: len(doc.Seccomp.BlockedSocketFamilies),
		Syscalls:              len(doc.Seccomp.Syscalls.Block),
	}
	return doc, info, nil
}

func readBuiltinMitigation(id string) ([]byte, bool, error) {
	data, err := builtinMitigationFS.ReadFile(mitigationFSPath(id))
	if err == nil {
		return data, true, nil
	}
	if errorsIsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("read built-in mitigation %q: %w", id, err)
}

func readExternalMitigation(id string, dirs []string) ([]byte, string, bool, error) {
	var foundPath string
	for _, dir := range dirs {
		for _, name := range []string{id + ".yaml", id + ".yml"} {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return nil, "", false, fmt.Errorf("stat external mitigation %q: %w", candidate, err)
			}
			if foundPath != "" {
				return nil, "", false, fmt.Errorf("mitigation set %q found in multiple external files: %q and %q", id, foundPath, candidate)
			}
			foundPath = candidate
		}
	}
	if foundPath == "" {
		return nil, "", false, nil
	}
	if err := validateMitigationPathPermissions(foundPath); err != nil {
		return nil, "", false, err
	}
	data, err := os.ReadFile(foundPath)
	if err != nil {
		return nil, "", false, fmt.Errorf("read external mitigation %q: %w", foundPath, err)
	}
	return data, foundPath, true, nil
}

func decodeMitigation(requestedID string, data []byte, source string) (mitigationDocument, error) {
	var doc mitigationDocument
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return mitigationDocument{}, fmt.Errorf("parse mitigation %q: %w", source, err)
	}
	if doc.Version != 1 {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: version must be 1", source)
	}
	if doc.ID != requestedID {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: id %q does not match requested id %q", source, doc.ID, requestedID)
	}
	if len(doc.Seccomp.SocketRules) == 0 &&
		len(doc.Seccomp.BlockedSocketFamilies) == 0 &&
		len(doc.Seccomp.Syscalls.Block) == 0 {
		return mitigationDocument{}, fmt.Errorf("mitigation %q: empty mitigations are not allowed", source)
	}
	return doc, nil
}

func mitigationFSPath(id string) string {
	return filepath.ToSlash(filepath.Join("mitigations", id+".yaml"))
}

func errorsIsNotExist(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, fs.ErrNotExist)
}
```

- [ ] **Step 5: Replace hardcoded socket profile expansion**

In `internal/config/seccomp_socket_rules.go`, change `ResolveSocketRules` and remove `effectiveSocketRuleConfigs`:

```go
func ResolveSocketRules(in SandboxSeccompConfig) ([]seccomp.SocketRule, error) {
	effective, err := EffectiveSeccompRulesForConfig(in)
	if err != nil {
		return nil, err
	}
	return resolveSocketRuleConfigs(effective.SocketRules)
}

func resolveSocketRuleConfigs(configs []SandboxSeccompSocketRuleConfig) ([]seccomp.SocketRule, error) {
	out := make([]seccomp.SocketRule, 0, len(configs))
	seen := map[string]struct{}{}
	for i, e := range configs {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return nil, fmt.Errorf("socket_rules[%d].name: required", i)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate socket rule name %q", name)
		}
		seen[name] = struct{}{}

		family, familyName, ok := seccomp.ParseFamily(e.Family)
		if !ok {
			return nil, fmt.Errorf("socket_rules[%d].family: %q is not valid", i, e.Family)
		}
		actionStr := e.Action
		if actionStr == "" {
			actionStr = string(seccomp.OnBlockErrno)
		}
		action, ok := seccomp.ParseOnBlock(actionStr)
		if !ok {
			return nil, fmt.Errorf("socket_rules[%d].action: %q is not valid (allowed: errno, kill, log, log_and_kill)", i, e.Action)
		}
		rule := seccomp.SocketRule{Name: name, Family: family, FamilyName: familyName, Action: action}
		if e.Type != "" {
			typ, typName, ok := seccomp.ParseSocketType(e.Type)
			if !ok {
				return nil, fmt.Errorf("socket_rules[%d].type: %q is not valid", i, e.Type)
			}
			rule.Type = &typ
			rule.TypeName = typName
		}
		if e.Protocol != "" {
			proto, protoName, ok := seccomp.ParseSocketProtocol(e.Protocol)
			if !ok {
				return nil, fmt.Errorf("socket_rules[%d].protocol: %q is not valid", i, e.Protocol)
			}
			if strings.HasPrefix(protoName, "NETLINK_") && family != afNetlinkFamily {
				return nil, fmt.Errorf("socket_rules[%d].protocol: %q requires family AF_NETLINK", i, e.Protocol)
			}
			rule.Protocol = &proto
			rule.ProtocolName = protoName
		}
		out = append(out, rule)
	}
	return out, nil
}
```

- [ ] **Step 6: Run tests to verify pass**

Run:

```bash
go test ./internal/config -run 'EffectiveSeccompRules|ResolveSocketRules_BuiltInDirtyFrag' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/config/mitigations/dirtyfrag-conservative.yaml internal/config/seccomp_mitigations.go internal/config/seccomp_mitigations_test.go internal/config/seccomp_socket_rules.go
git commit -m "config: load built-in YAML mitigation sets"
```

## Task 3: External Mitigation Directories and Guardrails

**Files:**
- Create: `internal/config/seccomp_mitigations_unix.go`
- Create: `internal/config/seccomp_mitigations_other.go`
- Modify: `internal/config/seccomp_mitigations_test.go`

- [ ] **Step 1: Add failing external mitigation tests**

Append to `internal/config/seccomp_mitigations_test.go`:

```go
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
```

Update the test imports:

```go
import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Add failing Unix permission test**

Append to `internal/config/seccomp_mitigations_test.go`:

```go
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
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
go test ./internal/config -run 'EffectiveSeccompRules_External|EffectiveSeccompRules_Rejects' -count=1
```

Expected: FAIL until permission helpers and all guardrails are wired correctly.

- [ ] **Step 4: Add Unix permission helper**

Create `internal/config/seccomp_mitigations_unix.go`:

```go
//go:build linux || darwin

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func validateMitigationPathPermissions(filePath string) error {
	dir := filepath.Dir(filePath)
	for _, path := range []string{dir, filePath} {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat mitigation path %q: %w", path, err)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("mitigation path %q is world-writable", path)
		}
	}
	return nil
}
```

- [ ] **Step 5: Add non-Unix permission helper**

Create `internal/config/seccomp_mitigations_other.go`:

```go
//go:build !linux && !darwin

package config

func validateMitigationPathPermissions(filePath string) error {
	return nil
}
```

- [ ] **Step 6: Fix loader imports and behavior**

Ensure `internal/config/seccomp_mitigations.go` imports `errors` and uses only `filepath.Join` for filesystem paths:

```go
import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)
```

Verify `readExternalMitigation` checks both `.yaml` and `.yml`, rejects duplicate external files, validates permissions before reading, and never lists the directory.

- [ ] **Step 7: Run tests to verify pass**

Run:

```bash
go test ./internal/config -run 'EffectiveSeccompRules_External|EffectiveSeccompRules_Rejects' -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/config/seccomp_mitigations.go internal/config/seccomp_mitigations_unix.go internal/config/seccomp_mitigations_other.go internal/config/seccomp_mitigations_test.go
git commit -m "config: support external mitigation directories"
```

## Task 4: Effective Seccomp Merge Helpers

**Files:**
- Modify: `internal/config/seccomp_mitigations.go`
- Modify: `internal/config/seccomp_mitigations_test.go`
- Modify: `internal/config/seccomp_socket_rules_test.go`
- Modify: `internal/config/config.go`

- [ ] **Step 1: Add failing merge tests**

Append to `internal/config/seccomp_mitigations_test.go`:

```go
func TestEffectiveSeccompRules_MergesExternalFamiliesAndSyscalls(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mixed.yaml"), []byte(`
version: 1
id: mixed
seccomp:
  blocked_socket_families:
    - family: AF_ALG
      action: log
  syscalls:
    block:
      - ptrace
    on_block: log
`), 0o600))

	eff, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"mixed"},
		MitigationDirs: []string{dir},
		Syscalls: SandboxSeccompSyscallConfig{
			Block:   []string{"mount"},
			OnBlock: "log",
		},
		BlockedSocketFamilies: []SandboxSeccompSocketFamilyConfig{{
			Family: "AF_VSOCK",
			Action: "errno",
		}},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"mount", "ptrace"}, eff.SyscallBlock)
	require.Equal(t, "log", eff.SyscallOnBlock)
	require.Len(t, eff.BlockedSocketFamilies, 2)
	require.Equal(t, "AF_VSOCK", eff.BlockedSocketFamilies[0].Family)
	require.Equal(t, "AF_ALG", eff.BlockedSocketFamilies[1].Family)
}

func TestEffectiveSeccompRules_RejectsSyscallOnBlockConflict(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "conflict.yaml"), []byte(`
version: 1
id: conflict
seccomp:
  syscalls:
    block:
      - ptrace
    on_block: log_and_kill
`), 0o600))

	_, err := EffectiveSeccompRulesForConfig(SandboxSeccompConfig{
		MitigationSets: []string{"conflict"},
		MitigationDirs: []string{dir},
		Syscalls: SandboxSeccompSyscallConfig{
			OnBlock: "errno",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "conflicts with effective sandbox.seccomp.syscalls.on_block")
}

func TestResolveEffectiveBlockedFamilies_MitigationSet(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "family.yaml"), []byte(`
version: 1
id: family
seccomp:
  blocked_socket_families:
    - family: AF_ALG
      action: log
`), 0o600))

	families, err := ResolveEffectiveBlockedFamilies(SandboxSeccompConfig{
		MitigationSets: []string{"family"},
		MitigationDirs: []string{dir},
	})
	require.NoError(t, err)
	require.Len(t, families, 1)
	require.Equal(t, "AF_ALG", families[0].Name)
	require.Equal(t, seccomp.OnBlockLog, families[0].Action)
}

func TestEffectiveSyscallBlock_MitigationSet(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "syscalls.yaml"), []byte(`
version: 1
id: syscalls
seccomp:
  syscalls:
    block:
      - ptrace
`), 0o600))

	block, action, err := EffectiveSyscallBlock(SandboxSeccompConfig{
		MitigationSets: []string{"syscalls"},
		MitigationDirs: []string{dir},
		Syscalls: SandboxSeccompSyscallConfig{
			Block:   []string{"mount"},
			OnBlock: "errno",
		},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"mount", "ptrace"}, block)
	require.Equal(t, "errno", action)
}
```

- [ ] **Step 2: Update stale hardening profile tests**

In `internal/config/seccomp_socket_rules_test.go`, replace the old `TestResolveSocketRules_DirtyFragProfile` with a `MitigationSets` version. Keep the alias test explicit:

```go
func TestResolveSocketRules_DirtyFragMitigationSet(t *testing.T) {
	cfg := SandboxSeccompConfig{
		MitigationSets: []string{"dirtyfrag-conservative"},
	}
	rules, err := ResolveSocketRules(cfg)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", rules[0].Name)
	require.Equal(t, "dirtyfrag-conservative-xfrm", rules[1].Name)
}

func TestResolveSocketRules_HardeningProfilesDeprecatedAlias(t *testing.T) {
	cfg := SandboxSeccompConfig{
		HardeningProfiles: []string{"dirtyfrag-conservative"},
	}
	rules, err := ResolveSocketRules(cfg)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", rules[0].Name)
	require.Equal(t, "dirtyfrag-conservative-xfrm", rules[1].Name)
}
```

Update unknown-profile and duplicate-name tests to use `MitigationSets` and expect `mitigation_sets[0]` in errors.

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
go test ./internal/config -run 'EffectiveSeccompRules_Merges|EffectiveSyscallBlock|ResolveEffectiveBlockedFamilies|DirtyFragMitigationSet|HardeningProfilesDeprecatedAlias' -count=1
```

Expected: FAIL because effective helper functions are missing.

- [ ] **Step 4: Add effective helper functions**

In `internal/config/seccomp_mitigations.go`, add:

```go
func ResolveEffectiveBlockedFamilies(in SandboxSeccompConfig) ([]seccomp.BlockedFamily, error) {
	effective, err := EffectiveSeccompRulesForConfig(in)
	if err != nil {
		return nil, err
	}
	return ResolveBlockedFamilies(effective.BlockedSocketFamilies)
}

func EffectiveSyscallBlock(in SandboxSeccompConfig) ([]string, string, error) {
	effective, err := EffectiveSeccompRulesForConfig(in)
	if err != nil {
		return nil, "", err
	}
	return effective.SyscallBlock, effective.SyscallOnBlock, nil
}
```

Add the seccomp import:

```go
	"github.com/agentsh/agentsh/internal/seccomp"
```

- [ ] **Step 5: Validate effective config in config validation**

In `internal/config/config.go`, replace the direct socket-rule validation block at the end of `validateConfig` with effective validation:

```go
	effective, err := EffectiveSeccompRulesForConfig(cfg.Sandbox.Seccomp)
	if err != nil {
		return fmt.Errorf("sandbox.seccomp.%w", err)
	}
	if _, err := ResolveBlockedFamilies(effective.BlockedSocketFamilies); err != nil {
		return fmt.Errorf("sandbox.seccomp.%w", err)
	}
	if _, err := resolveSocketRuleConfigs(effective.SocketRules); err != nil {
		return fmt.Errorf("sandbox.seccomp.%w", err)
	}
	for _, loaded := range effective.LoadedMitigations {
		slog.Info("seccomp mitigation loaded",
			"id", loaded.ID,
			"source", loaded.Source,
			"path", loaded.Path,
			"checksum", loaded.Checksum,
			"socket_rules", loaded.SocketRules,
			"blocked_socket_families", loaded.BlockedSocketFamilies,
			"syscalls", loaded.Syscalls)
	}
```

Leave the existing raw `blocked_socket_families` validation in place before this block. The effective `ResolveBlockedFamilies` call is the additional validation that covers mitigation-derived families.

- [ ] **Step 6: Run tests to verify pass**

Run:

```bash
go test ./internal/config -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/config/seccomp_mitigations.go internal/config/seccomp_mitigations_test.go internal/config/seccomp_socket_rules.go internal/config/seccomp_socket_rules_test.go
git commit -m "config: merge mitigation sets into effective seccomp rules"
```

## Task 5: Runtime Wiring

**Files:**
- Modify: `internal/api/seccomp_wrapper_config.go`
- Modify: `internal/api/blocklist_config_linux.go`
- Modify: `internal/api/wrap.go`
- Modify: `internal/api/app_ptrace_linux.go`
- Modify: `internal/api/blocklist_config_linux_test.go`
- Modify: `internal/api/socket_rule_checker_ptrace_linux_test.go`
- Modify: `internal/api/wrap_test.go`

- [ ] **Step 1: Add failing API tests for mitigation-set wiring**

Update existing Dirty Frag API tests that set `HardeningProfiles` to use:

```go
cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
```

Add this wrapper config test to `internal/api/wrap_test.go` near the socket-rule wrapper tests:

```go
func TestWrapInit_SeccompConfigContent_MitigationSetsForwardSocketRules(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("wrap is Linux-only")
	}

	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.UnixSockets.Enabled = &enabled
	cfg.Sandbox.UnixSockets.WrapperBin = "/bin/true"
	cfg.Sandbox.Seccomp.MitigationSets = []string{"dirtyfrag-conservative"}
	app, mgr := newTestAppForWrap(t, cfg)

	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	resp, _, err := app.wrapInitCore(s, s.ID, types.WrapInitRequest{
		AgentCommand: "/bin/echo",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SeccompConfig == "" {
		t.Fatal("expected seccomp config")
	}

	var parsed seccompWrapperConfig
	require.NoError(t, json.Unmarshal([]byte(resp.SeccompConfig), &parsed))
	require.Len(t, parsed.SocketRules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", parsed.SocketRules[0].Name)
	require.Equal(t, "dirtyfrag-conservative-xfrm", parsed.SocketRules[1].Name)
}
```

- [ ] **Step 2: Run API tests to verify failure**

Run:

```bash
go test ./internal/api -run 'MitigationSets|DirtyFrag|SocketRuleChecker|SeccompConfigContent' -count=1
```

Expected: FAIL where runtime code still reads raw `BlockedSocketFamilies` or `Syscalls.Block`.

- [ ] **Step 3: Update wrapper config construction**

In `internal/api/seccomp_wrapper_config.go`, change the initial syscall fields:

```go
	blockedSyscalls, onBlock, err := config.EffectiveSyscallBlock(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("seccomp: failed to resolve effective syscall block list; syscall rules will not be blocked", "error", err)
	}
	seccompCfg := seccompWrapperConfig{
		UnixSocketEnabled:   p.UnixSocketEnabled,
		SignalFilterEnabled: p.SignalFilterEnabled,
		ExecveEnabled:       p.ExecveEnabled,
		FileMonitorEnabled:  config.FileMonitorBoolWithDefault(a.cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
		BlockedSyscalls:     blockedSyscalls,
		OnBlock:             onBlock,
		ServerPID:           os.Getpid(),
	}
```

Replace family resolution:

```go
	families, err := config.ResolveEffectiveBlockedFamilies(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("seccomp: failed to resolve blocked_socket_families; families will not be blocked", "error", err)
	} else {
		seccompCfg.BlockedFamilies = families
	}
```

Keep `ResolveSocketRules(a.cfg.Sandbox.Seccomp)` for socket tuple rules because it now resolves mitigation sets.

- [ ] **Step 4: Update notify blocklist config**

In `internal/api/blocklist_config_linux.go`, replace raw syscall and family reads:

```go
	block, onBlock, err := config.EffectiveSyscallBlock(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("blocklist: failed to resolve effective syscall block list",
			"session_id", sessionID, "error", err)
	} else if action, ok := seccompkg.ParseOnBlock(onBlock); ok && (action == seccompkg.OnBlockLog || action == seccompkg.OnBlockLogAndKill) {
		nrs, skipped := seccompkg.ResolveSyscalls(block)
		if len(skipped) > 0 {
			slog.Warn("blocklist: some syscalls could not be resolved on this arch",
				"session_id", sessionID, "skipped", skipped, "arch", runtime.GOARCH)
		}
		cfg.ActionByNr = make(map[uint32]seccompkg.OnBlockAction, len(nrs))
		for _, nr := range nrs {
			cfg.ActionByNr[uint32(nr)] = action
		}
	}

	families, err := config.ResolveEffectiveBlockedFamilies(a.cfg.Sandbox.Seccomp)
	if err != nil {
		slog.Warn("blocklist: failed to resolve blocked_socket_families for notify dispatch",
			"session_id", sessionID, "error", err)
	} else {
		for _, bf := range families {
			if bf.Action != seccompkg.OnBlockLog && bf.Action != seccompkg.OnBlockLogAndKill {
				continue
			}
			if cfg.FamilyByKey == nil {
				cfg.FamilyByKey = make(map[uint64]seccompkg.BlockedFamily)
			}
			cfg.FamilyByKey[uint64(unix.SYS_SOCKET)<<32|uint64(bf.Family)] = bf
			cfg.FamilyByKey[uint64(unix.SYS_SOCKETPAIR)<<32|uint64(bf.Family)] = bf
		}
	}
```

- [ ] **Step 5: Update user-notify gating**

In `internal/api/wrap.go`, change `mainFilterUsesUserNotify`:

```go
	block, onBlock, err := config.EffectiveSyscallBlock(a.cfg.Sandbox.Seccomp)
	if err == nil && blockListUsesNotify(block, onBlock) {
		return true
	}
	if blockedFamiliesUseNotifyForSeccomp(a.cfg.Sandbox.Seccomp) {
		return true
	}
	if seccompSocketRulesUseNotify(a.cfg.Sandbox.Seccomp) {
		return true
	}
```

Add a helper near `blockedFamiliesUsesNotify`:

```go
func blockedFamiliesUseNotifyForSeccomp(seccompCfg config.SandboxSeccompConfig) bool {
	families, err := config.ResolveEffectiveBlockedFamilies(seccompCfg)
	if err != nil {
		slog.Warn("seccomp: failed to resolve blocked_socket_families; socket family rules will not use user notify", "error", err)
		return false
	}
	for _, f := range families {
		if f.Action == seccomppkg.OnBlockLog || f.Action == seccomppkg.OnBlockLogAndKill {
			return true
		}
	}
	return false
}
```

Keep `blockedFamiliesUsesNotify` only if existing tests still use it directly; otherwise remove it after updating tests.

- [ ] **Step 6: Update ptrace family resolution**

In `internal/api/app_ptrace_linux.go`, replace direct family calls:

```go
func resolveFamilyCheckerForPtrace(cfg *config.Config, emit ptrace.FamilyEmitter) (*ptrace.FamilyChecker, error) {
	families, err := config.ResolveEffectiveBlockedFamilies(cfg.Sandbox.Seccomp)
	if err != nil {
		return nil, err
	}
	if len(families) == 0 {
		return nil, nil
	}
	return ptrace.NewFamilyCheckerWithEmitter(families, emit), nil
}
```

Update log-count and orphan-warning paths to use `ResolveEffectiveBlockedFamilies`. Keep `ResolveSocketRules` for tuple rules because it now resolves mitigation sets.

- [ ] **Step 7: Run API tests to verify pass**

Run:

```bash
go test ./internal/api -run 'MitigationSets|DirtyFrag|SocketRuleChecker|SeccompConfigContent|mainFilterUsesUserNotify|BlockListConfig' -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/api/seccomp_wrapper_config.go internal/api/blocklist_config_linux.go internal/api/wrap.go internal/api/app_ptrace_linux.go internal/api/*test.go
git commit -m "api: apply mitigation sets to runtime seccomp wiring"
```

## Task 6: Docs and Example Config

**Files:**
- Modify: `docs/seccomp.md`
- Modify: `config.yml`
- Modify: any tests or comments found by `rg "hardening_profiles|dirtyfrag-conservative"`

- [ ] **Step 1: Update docs and config examples**

In `docs/seccomp.md`, replace the Dirty Frag section with:

````markdown
### Mitigation Sets

`sandbox.seccomp.mitigation_sets` loads named mitigation YAML files and expands them into ordinary seccomp rules. agentsh ships built-in mitigations and can also load external mitigation files from opt-in `mitigation_dirs`.

```yaml
sandbox:
  seccomp:
    mitigation_sets:
      - dirtyfrag-conservative
    mitigation_dirs:
      - /etc/agentsh/mitigations
```

The built-in `dirtyfrag-conservative` set is a conservative mitigation for the Openwall Dirty Frag advisory dated May 7, 2026. It expands to two `socket_rules`: one for `AF_RXRPC`, and one for `AF_NETLINK` with protocol `NETLINK_XFRM`. It does not block all `AF_NETLINK`.
````

In `config.yml`, replace the commented `hardening_profiles` example:

```yaml
    # Advisory mitigation sets. Built-ins are embedded in agentsh; external
    # directories are optional and only requested IDs are loaded.
    # mitigation_sets:
    #   - dirtyfrag-conservative
    # mitigation_dirs:
    #   - /etc/agentsh/mitigations
```

- [ ] **Step 2: Search for stale public wording**

Run:

```bash
rg -n "hardening_profiles|hardening profile|Dirty Frag" docs config.yml internal
```

Expected: no public docs prefer `hardening_profiles`. Remaining `hardening_profiles` hits should be code comments or alias tests that explicitly call it deprecated.

- [ ] **Step 3: Run focused docs/config tests**

Run:

```bash
go test ./internal/config ./internal/api -run 'MitigationSets|HardeningProfiles|DirtyFrag|SeccompConfigContent' -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add docs/seccomp.md config.yml internal
git commit -m "docs: document YAML mitigation sets"
```

## Task 7: Final Verification

**Files:**
- No planned edits.

- [ ] **Step 1: Run focused config and enforcement tests**

Run:

```bash
go test ./internal/config ./internal/api ./internal/netmonitor/unix ./internal/ptrace -run 'MitigationSets|HardeningProfiles|DirtyFrag|SocketRule|SocketRules|BlockListConfig|mainFilterUsesUserNotify|FamilyChecker' -count=1
```

Expected: PASS.

- [ ] **Step 2: Run Dirty Frag subprocess regression tests**

Run:

```bash
GOMAXPROCS=1 go test ./internal/netmonitor/unix -run 'TestDirtyFrag|TestSeccompSocketRuleBlock_Notify_LogDispatched|TestSeccompSocketRuleBlock_ErrnoTuple' -count=1 -timeout=60s -v
```

Expected: PASS. The `NETLINK_ROUTE` test must still avoid `seccomp_socket_rule_blocked`.

- [ ] **Step 3: Run full repository tests**

Run:

```bash
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 4: Run required Windows compilation check**

Run:

```bash
GOOS=windows go build ./...
```

Expected: exit 0.

- [ ] **Step 5: Check formatting and diff hygiene**

Run:

```bash
gofmt -w internal/config internal/api
git diff --check
git status --short
```

Expected: `git diff --check` exits 0. `git status --short` shows only intentional tracked changes plus any pre-existing untracked `.agentsh/` directory.

- [ ] **Step 6: Commit verification fixes if needed**

If verification required fixes, commit only those fixes:

```bash
git add <fixed-files>
git commit -m "fix: stabilize YAML mitigation set wiring"
```

Expected: no commit is made when verification does not require file changes.
