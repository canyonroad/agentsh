# Dirty Frag Socket Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in `dirtyfrag-conservative` hardening profile backed by generic socket tuple rules that block `AF_RXRPC` and only `AF_NETLINK + NETLINK_XFRM`.

**Architecture:** Add resolved socket-rule types in `internal/seccomp`, YAML/profile expansion in `internal/config`, pass effective rules into `agentsh-unixwrap`, install arg-aware seccomp rules in the existing Linux filter, and route notify-mode socket rule hits through a new audit event. Keep existing `blocked_socket_families` behavior unchanged.

**Tech Stack:** Go, libseccomp-golang, Linux seccomp user notify, ptrace fallback, YAML config, existing agentsh policy/audit event types.

---

## File Structure

- `internal/seccomp/families.go`: add `AF_RXRPC` to the family parser.
- `internal/seccomp/socket_rules.go`: new resolved socket-rule model plus family/type/protocol parsers.
- `internal/seccomp/socket_rules_test.go`: parser and matcher unit tests.
- `internal/config/config.go`: add YAML fields and validation hook.
- `internal/config/seccomp_socket_rules.go`: new profile expansion and resolver from YAML config to engine rules.
- `internal/config/seccomp_socket_rules_test.go`: config parsing, validation, profile expansion, duplicate detection.
- `internal/api/seccomp_wrapper_config.go`: serialize resolved socket rules into wrapper config.
- `cmd/agentsh-unixwrap/config.go`: deserialize socket rules.
- `cmd/agentsh-unixwrap/main.go`: pass socket rules into the Linux filter config.
- `internal/api/wrap.go` and `internal/api/core.go`: include socket rules in user-notify gating.
- `internal/api/wrap_test.go`: user-notify gating tests for socket rules.
- `internal/api/blocklist_config_linux.go`: pass notify-mode socket rules to the notify dispatcher.
- `internal/netmonitor/unix/seccomp_linux.go`: install seccomp conditional rules and expose notify-mode socket rules from `Filter`.
- `internal/netmonitor/unix/blocklist_linux.go`: match and handle socket-rule notifications; emit `seccomp_socket_rule_blocked`.
- `internal/netmonitor/unix/seccomp_socket_rule_test.go`: Linux/cgo seccomp tests for allow/block/audit behavior.
- `internal/ptrace/socket_rule_checker.go`: ptrace matcher and actions for socket tuple rules.
- `internal/ptrace/socket_rule_checker_test.go`: ptrace matcher/action tests.
- `internal/api/app_ptrace_linux.go`: wire socket-rule checker into ptrace config.
- `docs/seccomp.md`: document `socket_rules` and `dirtyfrag-conservative`.
- `config.yml`: add commented example for the opt-in hardening profile.

### Task 1: Engine Socket Rule Types And Parsers

**Files:**
- Modify: `internal/seccomp/families.go`
- Create: `internal/seccomp/socket_rules.go`
- Create: `internal/seccomp/socket_rules_test.go`

- [ ] **Step 1: Write parser tests**

Add `internal/seccomp/socket_rules_test.go`:

```go
package seccomp

import "testing"

func TestParseFamilyIncludesRxRPC(t *testing.T) {
	nr, name, ok := ParseFamily("AF_RXRPC")
	if !ok {
		t.Fatal("AF_RXRPC should parse")
	}
	if nr != 33 || name != "AF_RXRPC" {
		t.Fatalf("ParseFamily(AF_RXRPC) = (%d, %q), want (33, AF_RXRPC)", nr, name)
	}
}

func TestParseSocketProtocol(t *testing.T) {
	cases := []struct {
		in       string
		wantNr   int
		wantName string
		wantOK   bool
	}{
		{"NETLINK_XFRM", 6, "NETLINK_XFRM", true},
		{"NETLINK_ROUTE", 0, "NETLINK_ROUTE", true},
		{"6", 6, "", true},
		{"255", 255, "", true},
		{"NETLINK_NOT_REAL", 0, "", false},
		{"-1", 0, "", false},
		{"256", 0, "", false},
		{"9999", 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			gotNr, gotName, gotOK := ParseSocketProtocol(tc.in)
			if gotNr != tc.wantNr || gotName != tc.wantName || gotOK != tc.wantOK {
				t.Fatalf("ParseSocketProtocol(%q) = (%d, %q, %v), want (%d, %q, %v)",
					tc.in, gotNr, gotName, gotOK, tc.wantNr, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestParseSocketType(t *testing.T) {
	cases := []struct {
		in       string
		wantNr   int
		wantName string
		wantOK   bool
	}{
		{"SOCK_STREAM", 1, "SOCK_STREAM", true},
		{"SOCK_DGRAM", 2, "SOCK_DGRAM", true},
		{"SOCK_SEQPACKET", 5, "SOCK_SEQPACKET", true},
		{"3", 3, "", true},
		{"SOCK_NOT_REAL", 0, "", false},
		{"0", 0, "", false},
		{"9999", 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			gotNr, gotName, gotOK := ParseSocketType(tc.in)
			if gotNr != tc.wantNr || gotName != tc.wantName || gotOK != tc.wantOK {
				t.Fatalf("ParseSocketType(%q) = (%d, %q, %v), want (%d, %q, %v)",
					tc.in, gotNr, gotName, gotOK, tc.wantNr, tc.wantName, tc.wantOK)
			}
		})
	}
}

func TestSocketRuleMatches(t *testing.T) {
	proto := 6
	rule := SocketRule{
		Name:         "dirtyfrag-xfrm",
		Family:       16,
		FamilyName:   "AF_NETLINK",
		Protocol:     &proto,
		ProtocolName: "NETLINK_XFRM",
		Action:       OnBlockLogAndKill,
	}
	if !rule.MatchesSocket(16, 0, 6) {
		t.Fatal("expected NETLINK_XFRM socket to match")
	}
	if rule.MatchesSocket(16, 0, 0) {
		t.Fatal("NETLINK_ROUTE must not match NETLINK_XFRM rule")
	}
	if !rule.MatchesSocketpair(16, 0, 6) {
		t.Fatal("expected NETLINK_XFRM socketpair to match")
	}
	if rule.MatchesSocketpair(16, 0, 0) {
		t.Fatal("NETLINK_ROUTE socketpair must not match NETLINK_XFRM rule")
	}
}

func TestSocketRuleTypeMatchIgnoresFlags(t *testing.T) {
	typ := 1
	rule := SocketRule{Name: "stream", Family: 2, Type: &typ, Action: OnBlockErrno}
	if !rule.MatchesSocket(2, 1|SocketTypeFlagCloexec|SocketTypeFlagNonblock, 0) {
		t.Fatal("type matching should ignore SOCK_CLOEXEC and SOCK_NONBLOCK flags")
	}
}
```

- [ ] **Step 2: Run parser tests to verify they fail**

Run: `go test ./internal/seccomp -run 'TestParseFamilyIncludesRxRPC|TestParseSocketProtocol|TestParseSocketType|TestSocketRule' -v`

Expected: FAIL with undefined symbols such as `ParseSocketProtocol`, `SocketRule`, and missing `AF_RXRPC` parsing.

- [ ] **Step 3: Add engine model and parsers**

Update `internal/seccomp/families.go` by adding this entry to `nameTable`:

```go
"AF_RXRPC": 33,
```

Create `internal/seccomp/socket_rules.go`:

```go
package seccomp

import "strconv"

const (
	SocketTypeMask         = 0xf
	SocketTypeFlagNonblock = 0x800
	SocketTypeFlagCloexec  = 0x80000
)

// SocketRule is one resolved socket tuple block rule.
type SocketRule struct {
	Name         string        `json:"name,omitempty"`
	Family       int           `json:"family"`
	FamilyName   string        `json:"family_name,omitempty"`
	Type         *int          `json:"type,omitempty"`
	TypeName     string        `json:"type_name,omitempty"`
	Protocol     *int          `json:"protocol,omitempty"`
	ProtocolName string        `json:"protocol_name,omitempty"`
	Action       OnBlockAction `json:"action"`
}

var protocolNameTable = map[string]int{
	"NETLINK_ROUTE":          0,
	"NETLINK_USERSOCK":       2,
	"NETLINK_FIREWALL":       3,
	"NETLINK_SOCK_DIAG":      4,
	"NETLINK_NFLOG":          5,
	"NETLINK_XFRM":           6,
	"NETLINK_SELINUX":        7,
	"NETLINK_ISCSI":          8,
	"NETLINK_AUDIT":          9,
	"NETLINK_FIB_LOOKUP":     10,
	"NETLINK_CONNECTOR":      11,
	"NETLINK_NETFILTER":      12,
	"NETLINK_KOBJECT_UEVENT": 15,
	"NETLINK_GENERIC":        16,
}

var socketTypeNameTable = map[string]int{
	"SOCK_STREAM":    1,
	"SOCK_DGRAM":     2,
	"SOCK_RAW":       3,
	"SOCK_RDM":       4,
	"SOCK_SEQPACKET": 5,
}

// ParseSocketProtocol resolves a protocol name or numeric value.
func ParseSocketProtocol(value string) (nr int, name string, ok bool) {
	if value == "" {
		return 0, "", false
	}
	if n, found := protocolNameTable[value]; found {
		return n, value, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 || parsed > 255 {
		return 0, "", false
	}
	return parsed, "", true
}

// ParseSocketType resolves a socket type name or numeric value.
func ParseSocketType(value string) (nr int, name string, ok bool) {
	if value == "" {
		return 0, "", false
	}
	if n, found := socketTypeNameTable[value]; found {
		return n, value, true
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 || parsed > SocketTypeMask {
		return 0, "", false
	}
	return parsed, "", true
}

// MatchesSocket reports whether this rule applies to socket(2) arguments.
func (r SocketRule) MatchesSocket(family, typ, protocol uint64) bool {
	if uint64(r.Family) != family {
		return false
	}
	if r.Type != nil && uint64(*r.Type) != (typ&SocketTypeMask) {
		return false
	}
	if r.Protocol != nil && uint64(*r.Protocol) != protocol {
		return false
	}
	return true
}

// MatchesSocketpair reports whether this rule applies to socketpair(2) arguments.
func (r SocketRule) MatchesSocketpair(family, typ, protocol uint64) bool {
	if uint64(r.Family) != family {
		return false
	}
	if r.Type != nil && uint64(*r.Type) != (typ&SocketTypeMask) {
		return false
	}
	if r.Protocol != nil && uint64(*r.Protocol) != protocol {
		return false
	}
	return true
}
```

- [ ] **Step 4: Run parser tests to verify they pass**

Run: `go test ./internal/seccomp -run 'TestParseFamilyIncludesRxRPC|TestParseSocketProtocol|TestParseSocketType|TestSocketRule' -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/seccomp/families.go internal/seccomp/socket_rules.go internal/seccomp/socket_rules_test.go
git commit -m "feat(seccomp): add socket rule model"
```

### Task 2: YAML Config And Dirty Frag Profile Expansion

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/seccomp_socket_rules.go`
- Create: `internal/config/seccomp_socket_rules_test.go`

- [ ] **Step 1: Write config tests**

Add `internal/config/seccomp_socket_rules_test.go`:

```go
package config

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSandboxSeccompSocketRules_ParseYAML(t *testing.T) {
	data := []byte(`
sandbox:
  seccomp:
    socket_rules:
      - name: dirtyfrag-xfrm
        family: AF_NETLINK
        protocol: NETLINK_XFRM
        action: log_and_kill
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(data, &cfg))
	require.Len(t, cfg.Sandbox.Seccomp.SocketRules, 1)
	require.Equal(t, "dirtyfrag-xfrm", cfg.Sandbox.Seccomp.SocketRules[0].Name)
	require.Equal(t, "AF_NETLINK", cfg.Sandbox.Seccomp.SocketRules[0].Family)
	require.Equal(t, "NETLINK_XFRM", cfg.Sandbox.Seccomp.SocketRules[0].Protocol)
	require.Equal(t, "log_and_kill", cfg.Sandbox.Seccomp.SocketRules[0].Action)
}

func TestResolveSocketRules_DirtyFragProfile(t *testing.T) {
	cfg := SandboxSeccompConfig{
		HardeningProfiles: []string{"dirtyfrag-conservative"},
	}
	rules, err := ResolveSocketRules(cfg)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Equal(t, "dirtyfrag-conservative-rxrpc", rules[0].Name)
	require.Equal(t, 33, rules[0].Family)
	require.Equal(t, seccomp.OnBlockLogAndKill, rules[0].Action)
	require.Equal(t, "dirtyfrag-conservative-xfrm", rules[1].Name)
	require.Equal(t, 16, rules[1].Family)
	require.NotNil(t, rules[1].Protocol)
	require.Equal(t, 6, *rules[1].Protocol)
}

func TestResolveSocketRules_RejectsBadProtocol(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		SocketRules: []SandboxSeccompSocketRuleConfig{{
			Name: "bad",
			Family: "AF_NETLINK",
			Protocol: "NETLINK_XFRMM",
			Action: "errno",
		}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `socket_rules[0].protocol`)
	require.Contains(t, err.Error(), "NETLINK_XFRMM")
}

func TestResolveSocketRules_RejectsUnknownProfile(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		HardeningProfiles: []string{"dirtyfrag"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `hardening_profiles[0]`)
}

func TestResolveSocketRules_RejectsDuplicateNamesAfterProfileExpansion(t *testing.T) {
	_, err := ResolveSocketRules(SandboxSeccompConfig{
		SocketRules: []SandboxSeccompSocketRuleConfig{{
			Name: "dirtyfrag-conservative-xfrm",
			Family: "AF_NETLINK",
			Protocol: "NETLINK_XFRM",
			Action: "errno",
		}},
		HardeningProfiles: []string{"dirtyfrag-conservative"},
	})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "duplicate socket rule name"), err.Error())
}

func TestValidateConfig_ValidatesSocketRules(t *testing.T) {
	cfg := &Config{}
	cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	cfg.Sandbox.Seccomp.SocketRules = []SandboxSeccompSocketRuleConfig{{
		Name: "bad-family",
		Family: "AF_NOT_REAL",
		Action: "errno",
	}}
	err := validateConfig(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "AF_NOT_REAL")
}
```

- [ ] **Step 2: Run config tests to verify they fail**

Run: `go test ./internal/config -run 'TestSandboxSeccompSocketRules|TestResolveSocketRules|TestValidateConfig_ValidatesSocketRules' -v`

Expected: FAIL with undefined `SocketRules`, `HardeningProfiles`, and `ResolveSocketRules`.

- [ ] **Step 3: Add config schema**

In `internal/config/config.go`, extend `SandboxSeccompConfig`:

```go
type SandboxSeccompConfig struct {
	Enabled     bool                            `yaml:"enabled"`
	Mode        string                          `yaml:"mode"`
	UnixSocket  SandboxSeccompUnixConfig        `yaml:"unix_socket"`
	Syscalls    SandboxSeccompSyscallConfig     `yaml:"syscalls"`
	Execve      ExecveConfig                    `yaml:"execve"`
	FileMonitor SandboxSeccompFileMonitorConfig `yaml:"file_monitor"`

	BlockedSocketFamilies []SandboxSeccompSocketFamilyConfig `yaml:"blocked_socket_families"`
	SocketRules           []SandboxSeccompSocketRuleConfig   `yaml:"socket_rules"`
	HardeningProfiles     []string                           `yaml:"hardening_profiles"`
}
```

Add this struct near `SandboxSeccompSocketFamilyConfig`:

```go
type SandboxSeccompSocketRuleConfig struct {
	Name     string `yaml:"name"`
	Family   string `yaml:"family"`
	Type     string `yaml:"type,omitempty"`
	Protocol string `yaml:"protocol,omitempty"`
	Action   string `yaml:"action"`
}
```

- [ ] **Step 4: Add profile expansion and resolver**

Create `internal/config/seccomp_socket_rules.go`:

```go
package config

import (
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/internal/seccomp"
)

func ResolveSocketRules(in SandboxSeccompConfig) ([]seccomp.SocketRule, error) {
	configs, err := effectiveSocketRuleConfigs(in)
	if err != nil {
		return nil, err
	}
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
			rule.Protocol = &proto
			rule.ProtocolName = protoName
		}
		out = append(out, rule)
	}
	return out, nil
}

func effectiveSocketRuleConfigs(in SandboxSeccompConfig) ([]SandboxSeccompSocketRuleConfig, error) {
	out := make([]SandboxSeccompSocketRuleConfig, 0, len(in.SocketRules)+2*len(in.HardeningProfiles))
	out = append(out, in.SocketRules...)
	for i, profile := range in.HardeningProfiles {
		switch profile {
		case "dirtyfrag-conservative":
			out = append(out,
				SandboxSeccompSocketRuleConfig{
					Name: "dirtyfrag-conservative-rxrpc",
					Family: "AF_RXRPC",
					Action: "log_and_kill",
				},
				SandboxSeccompSocketRuleConfig{
					Name: "dirtyfrag-conservative-xfrm",
					Family: "AF_NETLINK",
					Protocol: "NETLINK_XFRM",
					Action: "log_and_kill",
				},
			)
		default:
			return nil, fmt.Errorf("hardening_profiles[%d]: unknown profile %q", i, profile)
		}
	}
	return out, nil
}
```

- [ ] **Step 5: Add validation hook**

In `internal/config/config.go`, inside `validateConfig` after the `blocked_socket_families` validation loop, add:

```go
if _, err := ResolveSocketRules(cfg.Sandbox.Seccomp); err != nil {
	return fmt.Errorf("sandbox.seccomp.%w", err)
}
```

- [ ] **Step 6: Run config tests to verify they pass**

Run: `go test ./internal/config -run 'TestSandboxSeccompSocketRules|TestResolveSocketRules|TestValidateConfig_ValidatesSocketRules' -v`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/config/seccomp_socket_rules.go internal/config/seccomp_socket_rules_test.go
git commit -m "feat(config): add seccomp socket rules"
```

### Task 3: Pass Socket Rules Into agentsh-unixwrap And Notify Gating

**Files:**
- Modify: `internal/api/seccomp_wrapper_config.go`
- Modify: `cmd/agentsh-unixwrap/config.go`
- Modify: `cmd/agentsh-unixwrap/main.go`
- Modify: `internal/netmonitor/unix/seccomp_linux.go`
- Modify: `internal/seccomp/filter.go`
- Modify: `internal/api/wrap.go`
- Modify: `internal/api/core.go`
- Modify: `internal/api/wrap_test.go`

- [ ] **Step 1: Write API gating tests**

Append to `internal/api/wrap_test.go`:

```go
func TestSocketRulesUsesNotify(t *testing.T) {
	cases := []struct {
		name  string
		rules []config.SandboxSeccompSocketRuleConfig
		want  bool
	}{
		{name: "empty", rules: nil, want: false},
		{name: "errno", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "errno"}}, want: false},
		{name: "kill", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "kill"}}, want: false},
		{name: "log", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "log"}}, want: true},
		{name: "log_and_kill", rules: []config.SandboxSeccompSocketRuleConfig{{Name: "x", Family: "AF_RXRPC", Action: "log_and_kill"}}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := socketRulesUsesNotify(tc.rules)
			if got != tc.want {
				t.Fatalf("socketRulesUsesNotify() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMainFilterUsesUserNotify_SocketRuleLog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mainFilterUsesUserNotify is Linux-only")
	}
	cfg := &config.Config{}
	disabled := false
	cfg.Sandbox.Seccomp.UnixSocket.Enabled = false
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &disabled
	cfg.Sandbox.Seccomp.FileMonitor.InterceptMetadata = &disabled
	cfg.Sandbox.Seccomp.SocketRules = []config.SandboxSeccompSocketRuleConfig{{
		Name: "dirtyfrag-xfrm",
		Family: "AF_NETLINK",
		Protocol: "NETLINK_XFRM",
		Action: "log",
	}}
	app := &App{cfg: cfg}
	if !app.mainFilterUsesUserNotify(false) {
		t.Fatal("mainFilterUsesUserNotify should return true when a socket rule uses log")
	}
}
```

- [ ] **Step 2: Run API gating tests to verify they fail**

Run: `go test ./internal/api -run 'TestSocketRulesUsesNotify|TestMainFilterUsesUserNotify_SocketRuleLog' -v`

Expected: FAIL with undefined `socketRulesUsesNotify`.

- [ ] **Step 3: Add fields and forwarding**

In `internal/api/seccomp_wrapper_config.go`, add to `seccompWrapperConfig`:

```go
SocketRules []seccompkg.SocketRule `json:"socket_rules,omitempty"`
```

In `buildSeccompWrapperConfig`, after resolving `BlockedFamilies`, add:

```go
if rules, err := config.ResolveSocketRules(a.cfg.Sandbox.Seccomp); err != nil {
	slog.Warn("seccomp: failed to resolve socket_rules; socket rules will not be blocked", "error", err)
} else {
	seccompCfg.SocketRules = rules
}
```

In `cmd/agentsh-unixwrap/config.go`, add to `WrapperConfig`:

```go
SocketRules []seccompkg.SocketRule `json:"socket_rules,omitempty"`
```

In `internal/netmonitor/unix/seccomp_linux.go`, add to `FilterConfig`:

```go
SocketRules []seccompkg.SocketRule
```

In `internal/seccomp/filter.go`, add `SocketRules []SocketRule` to `FilterConfig` and update `FilterConfigFromYAML` to accept and set `socketRules []SocketRule`.

In `cmd/agentsh-unixwrap/main.go`, add to `unixmon.FilterConfig` construction:

```go
SocketRules: cfg.SocketRules,
```

- [ ] **Step 4: Add notify gating helper**

In `internal/api/wrap.go`, update `mainFilterUsesUserNotify` before the final `return false`:

```go
if socketRulesUsesNotify(a.cfg.Sandbox.Seccomp.SocketRules) {
	return true
}
```

Add helper near `blockedFamiliesUsesNotify`:

```go
func socketRulesUsesNotify(rules []config.SandboxSeccompSocketRuleConfig) bool {
	for _, r := range rules {
		if r.Action == "log" || r.Action == "log_and_kill" {
			return true
		}
	}
	return false
}
```

In `internal/api/core.go`, update `hasNotifyFeatures`:

```go
hasNotifyFeatures := seccompCfg.UnixSocketEnabled ||
	seccompCfg.ExecveEnabled ||
	seccompCfg.FileMonitorEnabled ||
	seccompCfg.InterceptMetadata ||
	blockListUsesNotify(seccompCfg.BlockedSyscalls, seccompCfg.OnBlock) ||
	blockedFamiliesUsesNotify(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies) ||
	socketRulesUsesNotify(a.cfg.Sandbox.Seccomp.SocketRules)
```

- [ ] **Step 5: Run API gating tests to verify they pass**

Run: `go test ./internal/api -run 'TestSocketRulesUsesNotify|TestMainFilterUsesUserNotify_SocketRuleLog' -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/api/seccomp_wrapper_config.go cmd/agentsh-unixwrap/config.go cmd/agentsh-unixwrap/main.go internal/netmonitor/unix/seccomp_linux.go internal/seccomp/filter.go internal/api/wrap.go internal/api/core.go internal/api/wrap_test.go
git commit -m "feat(wrap): pass socket rules to seccomp wrapper"
```

### Task 4: Install Seccomp Socket Tuple Rules

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_linux.go`
- Create: `internal/netmonitor/unix/seccomp_socket_rule_test.go`

- [ ] **Step 1: Write filter map tests**

Create `internal/netmonitor/unix/seccomp_socket_rule_test.go`:

```go
//go:build linux && cgo

package unix

import (
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	gounix "golang.org/x/sys/unix"
)

func TestSeccompSocketRuleMap_LogActionsOnly(t *testing.T) {
	proto := 6
	cfg := FilterConfig{
		SocketRules: []seccompkg.SocketRule{
			{Name: "errno", Family: gounix.AF_NETLINK, Protocol: &proto, Action: seccompkg.OnBlockErrno},
			{Name: "log", Family: gounix.AF_NETLINK, Protocol: &proto, Action: seccompkg.OnBlockLog},
			{Name: "log-and-kill", Family: gounix.AF_RXRPC, Action: seccompkg.OnBlockLogAndKill},
			{Name: "kill", Family: gounix.AF_ALG, Action: seccompkg.OnBlockKill},
		},
	}
	filt := &Filter{socketRules: notifySocketRules(cfg.SocketRules)}
	got := filt.SocketRules()
	if len(got) != 2 {
		t.Fatalf("SocketRules() length = %d, want 2", len(got))
	}
	if got[0].Name != "log" || got[1].Name != "log-and-kill" {
		t.Fatalf("SocketRules() = %#v, want log and log-and-kill only", got)
	}
}
```

- [ ] **Step 2: Run filter map test to verify it fails**

Run: `go test ./internal/netmonitor/unix -run TestSeccompSocketRuleMap_LogActionsOnly -v`

Expected: FAIL with undefined `socketRules`, `SocketRules`, or `notifySocketRules`.

- [ ] **Step 3: Add filter storage and helper functions**

In `internal/netmonitor/unix/seccomp_linux.go`, extend `Filter`:

```go
type Filter struct {
	fd               seccomp.ScmpFd
	blockList        map[uint32]seccompkg.OnBlockAction
	blockedFamilyMap map[uint64]seccompkg.BlockedFamily
	socketRules      []seccompkg.SocketRule
}
```

Add method:

```go
func (f *Filter) SocketRules() []seccompkg.SocketRule {
	if f == nil || len(f.socketRules) == 0 {
		return nil
	}
	out := make([]seccompkg.SocketRule, len(f.socketRules))
	copy(out, f.socketRules)
	return out
}
```

Add helper functions near the family-rule helper code:

```go
func notifySocketRules(rules []seccompkg.SocketRule) []seccompkg.SocketRule {
	out := make([]seccompkg.SocketRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Action == seccompkg.OnBlockLog || rule.Action == seccompkg.OnBlockLogAndKill {
			out = append(out, rule)
		}
	}
	return out
}

func socketRuleConditions(rule seccompkg.SocketRule, includeProtocol bool) []seccomp.ScmpCondition {
	conds := []seccomp.ScmpCondition{{
		Argument: 0,
		Op:       seccomp.CompareEqual,
		Operand1: uint64(rule.Family),
	}}
	if rule.Type != nil {
		conds = append(conds, seccomp.ScmpCondition{
			Argument: 1,
			Op:       seccomp.CompareMaskedEqual,
			Operand1: uint64(seccompkg.SocketTypeMask),
			Operand2: uint64(*rule.Type),
		})
	}
	if includeProtocol && rule.Protocol != nil {
		conds = append(conds, seccomp.ScmpCondition{
			Argument: 2,
			Op:       seccomp.CompareEqual,
			Operand1: uint64(*rule.Protocol),
		})
	}
	return conds
}
```

- [ ] **Step 4: Install conditional rules**

In `InstallFilterWithConfig`, after blocked syscalls and before existing family rules, add:

```go
socketRuleCount := 0
socketNotifyRules := notifySocketRules(cfg.SocketRules)
for _, sr := range cfg.SocketRules {
	action, err := familyToScmpAction(sr.Action)
	if err != nil {
		slog.Warn("seccomp: skipping socket rule with unknown action",
			"rule", sr.Name, "action", sr.Action, "error", err)
		continue
	}
	if err := filt.AddRuleConditional(
		seccomp.ScmpSyscall(unix.SYS_SOCKET),
		action,
		socketRuleConditions(sr, true),
	); err != nil {
		slog.Warn("seccomp: failed to add socket rule",
			"rule", sr.Name, "syscall", "socket", "error", err)
	} else {
		socketRuleCount++
	}
	if err := filt.AddRuleConditional(
		seccomp.ScmpSyscall(unix.SYS_SOCKETPAIR),
		action,
		socketRuleConditions(sr, true),
	); err != nil {
		slog.Warn("seccomp: failed to add socket rule",
			"rule", sr.Name, "syscall", "socketpair", "error", err)
	} else {
		socketRuleCount++
	}
}
ruleCounts["socket_rules"] = socketRuleCount
```

When returning the `Filter`, set `socketRules: socketNotifyRules`. The return block is later in the same function; update it to include the new field:

```go
return &Filter{
	fd:               seccomp.ScmpFd(notifFD),
	blockList:        blockListMap,
	blockedFamilyMap: blockedFamilyMap,
	socketRules:      socketNotifyRules,
}, nil
```

Add diagnostics field in `filterDiagnosticFields`:

```go
"rules_socket_rules", ruleCounts["socket_rules"],
```

- [ ] **Step 5: Run filter map test to verify it passes**

Run: `go test ./internal/netmonitor/unix -run TestSeccompSocketRuleMap_LogActionsOnly -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/unix/seccomp_linux.go internal/netmonitor/unix/seccomp_socket_rule_test.go
git commit -m "feat(seccomp): install socket tuple rules"
```

### Task 5: Notify Dispatch And Audit Event

**Files:**
- Modify: `internal/netmonitor/unix/blocklist_linux.go`
- Modify: `internal/netmonitor/unix/handler.go`
- Modify: `internal/api/blocklist_config_linux.go`
- Modify: `internal/ocsf/registry.go`
- Modify: `internal/ocsf/project_finding.go`
- Modify: `internal/netmonitor/unix/seccomp_socket_rule_test.go`

- [ ] **Step 1: Write notify dispatch tests**

Append to `internal/netmonitor/unix/seccomp_socket_rule_test.go`:

```go
func TestBlockListConfigSocketRuleDispatch(t *testing.T) {
	proto := 6
	route := 0
	cfg := &BlockListConfig{SocketRules: []seccompkg.SocketRule{
		{Name: "dirtyfrag-xfrm", Family: gounix.AF_NETLINK, Protocol: &proto, Action: seccompkg.OnBlockLog},
	}}
	if _, ok := cfg.SocketRuleBlockListed(uint32(gounix.SYS_SOCKET), uint64(gounix.AF_NETLINK), 0, uint64(proto)); !ok {
		t.Fatal("NETLINK_XFRM socket should match")
	}
	if _, ok := cfg.SocketRuleBlockListed(uint32(gounix.SYS_SOCKET), uint64(gounix.AF_NETLINK), 0, uint64(route)); ok {
		t.Fatal("NETLINK_ROUTE socket should not match")
	}
	if _, ok := cfg.SocketRuleBlockListed(uint32(gounix.SYS_SOCKETPAIR), uint64(gounix.AF_NETLINK), 0, uint64(proto)); !ok {
		t.Fatal("NETLINK_XFRM socketpair should match")
	}
	if _, ok := cfg.SocketRuleBlockListed(uint32(gounix.SYS_SOCKETPAIR), uint64(gounix.AF_NETLINK), 0, uint64(route)); ok {
		t.Fatal("NETLINK_ROUTE socketpair should not match NETLINK_XFRM rule")
	}
}
```

- [ ] **Step 2: Run notify dispatch tests to verify they fail**

Run: `go test ./internal/netmonitor/unix -run TestBlockListConfigSocketRuleDispatch -v`

Expected: FAIL with undefined `SocketRules` or `SocketRuleBlockListed`.

- [ ] **Step 3: Add dispatch data and matcher**

In `internal/netmonitor/unix/blocklist_linux.go`, extend `BlockListConfig`:

```go
type BlockListConfig struct {
	ActionByNr  map[uint32]seccompkg.OnBlockAction
	FamilyByKey map[uint64]seccompkg.BlockedFamily
	SocketRules []seccompkg.SocketRule
}
```

Add method:

```go
func (c *BlockListConfig) SocketRuleBlockListed(syscallNr uint32, family, typ, protocol uint64) (seccompkg.SocketRule, bool) {
	if c == nil || len(c.SocketRules) == 0 {
		return seccompkg.SocketRule{}, false
	}
	for _, rule := range c.SocketRules {
		switch syscallNr {
		case uint32(unix.SYS_SOCKET):
			if rule.MatchesSocket(family, typ, protocol) {
				return rule, true
			}
		case uint32(unix.SYS_SOCKETPAIR):
			if rule.MatchesSocketpair(family, typ, protocol) {
				return rule, true
			}
		}
	}
	return seccompkg.SocketRule{}, false
}
```

- [ ] **Step 4: Forward notify-mode socket rules to BlockListConfig**

In `internal/api/blocklist_config_linux.go`, after family map population, add:

```go
if rules, err := config.ResolveSocketRules(a.cfg.Sandbox.Seccomp); err != nil {
	slog.Warn("blocklist: failed to resolve socket_rules for notify dispatch",
		"session_id", sessionID, "error", err)
} else {
	for _, rule := range rules {
		if rule.Action == seccompkg.OnBlockLog || rule.Action == seccompkg.OnBlockLogAndKill {
			cfg.SocketRules = append(cfg.SocketRules, rule)
		}
	}
}
```

- [ ] **Step 5: Add audit handler**

In `internal/netmonitor/unix/blocklist_linux.go`, add:

```go
func handleSocketRuleBlockNotify(
	ctx context.Context,
	fd int,
	req *seccomp.ScmpNotifReq,
	rule seccompkg.SocketRule,
	sessID string,
	emit Emitter,
) {
	if req == nil {
		return
	}
	if err := notifIDValidFn(fd, req.ID); err != nil {
		slog.Debug("seccomp socket-rule-block: notif id no longer valid",
			"session_id", sessID, "pid", req.Pid, "rule", rule.Name, "error", err)
		if derr := NotifRespondDeny(fd, req.ID, int32(unix.EAFNOSUPPORT)); derr != nil && !isENOENT(derr) {
			slog.Warn("seccomp socket-rule-block: deny response failed after invalid id",
				"session_id", sessID, "pid", req.Pid, "rule", rule.Name, "error", derr)
		}
		return
	}

	syscallNr := uint32(req.Data.Syscall)
	scName := resolveSyscallName(syscallNr)
	tid := int(req.Pid)

	outcome := "denied"
	if rule.Action == seccompkg.OnBlockLogAndKill {
		targetPID := tid
		if tgid, err := resolveTGIDFn(tid); err == nil {
			targetPID = tgid
		} else if errors.Is(err, unix.ESRCH) {
			targetPID = -1
		} else {
			slog.Warn("seccomp socket-rule-block: TGID resolution failed; falling back to TID",
				"session_id", sessID, "tid", tid, "rule", rule.Name, "error", err)
		}
		if targetPID == -1 {
			outcome = "killed"
		} else {
			outcome = attemptKill(fd, req.ID, targetPID, sessID, scName)
		}
	}

	if emit != nil {
		ev := types.Event{
			ID:        fmt.Sprintf("seccomp-%d-%d", tid, time.Now().UnixNano()),
			Timestamp: time.Now().UTC(),
			Type:      "seccomp_socket_rule_blocked",
			SessionID: sessID,
			Source:    "seccomp",
			PID:       tid,
			Fields: map[string]any{
				"rule":            rule.Name,
				"family":          rule.FamilyName,
				"family_number":   rule.Family,
				"type":            displayOptionalName(rule.TypeName, rule.Type),
				"type_number":     optionalInt(rule.Type),
				"protocol":        displayOptionalName(rule.ProtocolName, rule.Protocol),
				"protocol_number": optionalInt(rule.Protocol),
				"syscall":         scName,
				"syscall_nr":      syscallNr,
				"action":          string(rule.Action),
				"outcome":         outcome,
				"arch":            runtime.GOARCH,
				"engine":          "seccomp",
			},
		}
		if err := emit.AppendEvent(context.Background(), ev); err != nil {
			slog.Warn("seccomp socket-rule-block: AppendEvent failed",
				"session_id", sessID, "tid", tid, "rule", rule.Name, "error", err)
		}
		emit.Publish(ev)
	}

	_ = ctx
	if err := NotifRespondDeny(fd, req.ID, int32(unix.EAFNOSUPPORT)); err != nil && !isENOENT(err) {
		slog.Warn("seccomp socket-rule-block: deny response failed",
			"session_id", sessID, "tid", tid, "rule", rule.Name, "error", err)
	}
}

func displayOptionalName(name string, nr *int) string {
	if nr == nil {
		return "*"
	}
	if name != "" {
		return name
	}
	return ""
}

func optionalInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}
```

- [ ] **Step 6: Route socket rules before family and generic blocklist**

In `internal/netmonitor/unix/handler.go`, inside the existing `socket/socketpair` branch before `FamilyBlockListed`, add:

```go
if sr, ok := blockList.SocketRuleBlockListed(
	uint32(req.Data.Syscall),
	req.Data.Args[0],
	req.Data.Args[1],
	req.Data.Args[2],
); ok {
	slog.Debug("ServeNotifyWithExecve: routing to socket-rule-block handler",
		"session_id", sessID, "pid", req.Pid, "syscall_nr", syscallNr, "rule", sr.Name)
	handleSocketRuleBlockNotify(ctx, int(scmpFD), req, sr, sessID, emit)
	continue
}
```

- [ ] **Step 7: Register audit type**

In `internal/ocsf/registry.go`, add:

```go
"seccomp_socket_rule_blocked": {},
```

In `internal/ocsf/project_finding.go`, add:

```go
"seccomp_socket_rule_blocked": "policy_decision",
```

- [ ] **Step 8: Run notify dispatch tests to verify they pass**

Run: `go test ./internal/netmonitor/unix -run TestBlockListConfigSocketRuleDispatch -v`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/netmonitor/unix/blocklist_linux.go internal/netmonitor/unix/handler.go internal/api/blocklist_config_linux.go internal/ocsf/registry.go internal/ocsf/project_finding.go internal/netmonitor/unix/seccomp_socket_rule_test.go
git commit -m "feat(seccomp): audit socket rule blocks"
```

### Task 6: End-To-End Seccomp Behavior Tests

**Files:**
- Modify: `internal/netmonitor/unix/seccomp_socket_rule_test.go`

- [ ] **Step 1: Add subprocess integration tests**

Append to `internal/netmonitor/unix/seccomp_socket_rule_test.go`:

```go
func TestSeccompSocketRule_AllowsNetlinkRoute(t *testing.T) {
	if os.Getenv("AGENTSH_SOCKET_RULE_HELPER") == "route" {
		runSocketRuleHelper(t, 0)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompSocketRule_AllowsNetlinkRoute")
	cmd.Env = append(os.Environ(), "AGENTSH_SOCKET_RULE_HELPER=route")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "socket_result=allowed_or_kernel_denied") {
		t.Fatalf("unexpected helper output:\n%s", out)
	}
}

func TestSeccompSocketRule_BlocksNetlinkXFRM(t *testing.T) {
	if os.Getenv("AGENTSH_SOCKET_RULE_HELPER") == "xfrm" {
		runSocketRuleHelper(t, 6)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompSocketRule_BlocksNetlinkXFRM")
	cmd.Env = append(os.Environ(), "AGENTSH_SOCKET_RULE_HELPER=xfrm")
	out, err := cmd.CombinedOutput()
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted") {
			t.Skipf("host cannot install seccomp filter:\n%s", out)
		}
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "socket_errno=address family not supported by protocol") &&
		!strings.Contains(string(out), "socket_errno=protocol not supported") &&
		!strings.Contains(string(out), "socket_errno=97") {
		t.Fatalf("expected socket denial, got:\n%s", out)
	}
	if !strings.Contains(string(out), "audit_event=seccomp_socket_rule_blocked") {
		t.Fatalf("expected seccomp_socket_rule_blocked audit event:\n%s", out)
	}
}

func TestSeccompSocketRule_BlocksRxRPC(t *testing.T) {
	if os.Getenv("AGENTSH_SOCKET_RULE_HELPER") == "rxrpc" {
		runRxRPCHelper(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompSocketRule_BlocksRxRPC")
	cmd.Env = append(os.Environ(), "AGENTSH_SOCKET_RULE_HELPER=rxrpc")
	out, err := cmd.CombinedOutput()
	if err != nil {
		lower := strings.ToLower(string(out))
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted") {
			t.Skipf("host cannot install seccomp filter:\n%s", out)
		}
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "audit_event=seccomp_socket_rule_blocked") {
		t.Fatalf("expected seccomp_socket_rule_blocked audit event:\n%s", out)
	}
}

func runSocketRuleHelper(t *testing.T, protocol int) {
	t.Helper()
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	proto := 6
	cfg := FilterConfig{
		SocketRules: []seccompkg.SocketRule{{
			Name: "dirtyfrag-xfrm",
			Family: gounix.AF_NETLINK,
			FamilyName: "AF_NETLINK",
			Protocol: &proto,
			ProtocolName: "NETLINK_XFRM",
			Action: seccompkg.OnBlockLog,
		}},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()
	emitter := &captureEmitter{fn: func(typ string) { fmt.Printf("audit_event=%s\n", typ) }}
	bl := &BlockListConfig{SocketRules: filt.SocketRules()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeNotifyWithExecve(ctx, os.NewFile(uintptr(filt.NotifFD()), "seccomp"), "sess-test", nil, emitter, nil, nil, bl)
	fd, _, errno := gounix.Syscall(gounix.SYS_SOCKET, uintptr(gounix.AF_NETLINK), uintptr(gounix.SOCK_RAW), uintptr(protocol))
	if errno != 0 {
		fmt.Printf("socket_errno=%v\n", errno)
		return
	}
	_ = gounix.Close(int(fd))
	fmt.Println("socket_result=allowed_or_kernel_denied")
}

func runRxRPCHelper(t *testing.T) {
	t.Helper()
	if err := DetectSupport(); err != nil {
		t.Skipf("seccomp user-notify not supported: %v", err)
	}
	cfg := FilterConfig{
		SocketRules: []seccompkg.SocketRule{{
			Name: "dirtyfrag-rxrpc",
			Family: 33,
			FamilyName: "AF_RXRPC",
			Action: seccompkg.OnBlockLog,
		}},
	}
	filt, err := InstallFilterWithConfig(cfg)
	if err != nil {
		t.Fatalf("InstallFilterWithConfig: %v", err)
	}
	defer filt.Close()
	emitter := &captureEmitter{fn: func(typ string) { fmt.Printf("audit_event=%s\n", typ) }}
	bl := &BlockListConfig{SocketRules: filt.SocketRules()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeNotifyWithExecve(ctx, os.NewFile(uintptr(filt.NotifFD()), "seccomp"), "sess-test", nil, emitter, nil, nil, bl)
	_, _, errno := gounix.Syscall(gounix.SYS_SOCKET, uintptr(33), uintptr(gounix.SOCK_DGRAM), 0)
	fmt.Printf("socket_errno=%v\n", errno)
}
```

If the file does not already import these packages, update its import list with:

```go
import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	gounix "golang.org/x/sys/unix"
)
```

- [ ] **Step 2: Run seccomp integration tests**

Run: `go test ./internal/netmonitor/unix -run 'TestSeccompSocketRule_(AllowsNetlinkRoute|BlocksNetlinkXFRM|BlocksRxRPC)' -v`

Expected: PASS, or SKIP on hosts that cannot install seccomp user-notify filters.

- [ ] **Step 3: Run existing family tests to catch regressions**

Run: `go test ./internal/netmonitor/unix -run 'TestSeccompFamily|TestFamilyDispatchBeforeGenericBlocklist|TestSeccompSocketRule' -v`

Expected: PASS, or host-capability SKIP for integration cases.

- [ ] **Step 4: Commit**

```bash
git add internal/netmonitor/unix/seccomp_socket_rule_test.go
git commit -m "test(seccomp): cover dirtyfrag socket rules"
```

### Task 7: Documentation And Example Config

**Files:**
- Modify: `docs/seccomp.md`
- Modify: `config.yml`

- [ ] **Step 1: Update seccomp docs**

In `docs/seccomp.md`, after the "Socket Family Blocking" section, add:

```markdown
## Socket Tuple Rules

`sandbox.seccomp.socket_rules` blocks specific `socket(2)` tuples without denying an entire address family. Rules match `family`, optional `type`, and optional `protocol`.

```yaml
sandbox:
  seccomp:
    socket_rules:
      - name: dirtyfrag-xfrm
        family: AF_NETLINK
        protocol: NETLINK_XFRM
        action: log_and_kill
```

For `socket(2)`, agentsh matches:

- arg0: address family
- arg1: socket type, with `SOCK_CLOEXEC` and `SOCK_NONBLOCK` ignored
- arg2: protocol

For `socketpair(2)`, agentsh matches family, type, and protocol.

Supported actions are `errno`, `kill`, `log`, and `log_and_kill`. Socket-rule denials return `EAFNOSUPPORT`. `log` and `log_and_kill` emit `seccomp_socket_rule_blocked`.

### Dirty Frag Conservative Profile

`dirtyfrag-conservative` is an opt-in profile for the May 2026 Dirty Frag advisory. It expands to:

- `socket(AF_RXRPC, ...)` blocked with `log_and_kill`
- `socket(AF_NETLINK, *, NETLINK_XFRM)` blocked with `log_and_kill`

Enable it with:

```yaml
sandbox:
  seccomp:
    hardening_profiles:
      - dirtyfrag-conservative
```

The profile does not block normal `AF_NETLINK` protocols such as `NETLINK_ROUTE`, `NETLINK_KOBJECT_UEVENT`, or `NETLINK_GENERIC`. It also does not block keyring, namespace, or splice syscalls.
```

- [ ] **Step 2: Add commented example to config**

In `config.yml`, under `sandbox.seccomp`, add:

```yaml
    # Optional kernel attack-surface hardening profiles.
    # dirtyfrag-conservative blocks AF_RXRPC and NETLINK_XFRM without blocking
    # normal AF_NETLINK users such as ip(8), ss(8), and udev-style listeners.
    # hardening_profiles:
    #   - dirtyfrag-conservative
```

- [ ] **Step 3: Verify docs references**

Run: `rg -n "dirtyfrag-conservative|socket_rules|seccomp_socket_rule_blocked" docs/seccomp.md config.yml`

Expected: output includes all three terms.

- [ ] **Step 4: Commit**

```bash
git add docs/seccomp.md config.yml
git commit -m "docs(seccomp): document socket tuple rules"
```

### Task 8: Ptrace Socket Rule Parity

**Files:**
- Create: `internal/ptrace/socket_rule_checker.go`
- Create: `internal/ptrace/socket_rule_checker_test.go`
- Modify: `internal/ptrace/tracer.go`
- Modify: `internal/api/app_ptrace_linux.go`
- Modify: `internal/api/family_engine_linux.go`
- Modify: `internal/api/family_engine_linux_test.go`

- [ ] **Step 1: Write ptrace matcher tests**

Create `internal/ptrace/socket_rule_checker_test.go`:

```go
package ptrace

import (
	"testing"

	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

func TestSocketRuleCheckerCheck(t *testing.T) {
	proto := 6
	checker := NewSocketRuleChecker([]seccomp.SocketRule{{
		Name: "dirtyfrag-xfrm",
		Family: unix.AF_NETLINK,
		Protocol: &proto,
		Action: seccomp.OnBlockErrno,
	}})
	if _, ok := checker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), 0, 6); !ok {
		t.Fatal("expected NETLINK_XFRM to match")
	}
	if _, ok := checker.Check(uint64(unix.SYS_SOCKET), uint64(unix.AF_NETLINK), 0, 0); ok {
		t.Fatal("NETLINK_ROUTE must not match NETLINK_XFRM")
	}
	if _, ok := checker.Check(uint64(unix.SYS_SOCKETPAIR), uint64(unix.AF_NETLINK), 0, 6); !ok {
		t.Fatal("protocol rule should match socketpair")
	}
}
```

- [ ] **Step 2: Run ptrace matcher tests to verify they fail**

Run: `go test ./internal/ptrace -run TestSocketRuleCheckerCheck -v`

Expected: FAIL with undefined `NewSocketRuleChecker`.

- [ ] **Step 3: Add ptrace checker**

Create `internal/ptrace/socket_rule_checker.go`:

```go
package ptrace

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/agentsh/agentsh/internal/seccomp"
	"github.com/agentsh/agentsh/pkg/types"
	"golang.org/x/sys/unix"
)

type SocketRuleChecker struct {
	rules []seccomp.SocketRule
	emit  FamilyEmitter
}

func NewSocketRuleChecker(rules []seccomp.SocketRule) *SocketRuleChecker {
	return NewSocketRuleCheckerWithEmitter(rules, nil)
}

func NewSocketRuleCheckerWithEmitter(rules []seccomp.SocketRule, emit FamilyEmitter) *SocketRuleChecker {
	cp := make([]seccomp.SocketRule, len(rules))
	copy(cp, rules)
	return &SocketRuleChecker{rules: cp, emit: emit}
}

func (c *SocketRuleChecker) Check(syscall, family, typ, protocol uint64) (seccomp.SocketRule, bool) {
	if c == nil {
		return seccomp.SocketRule{}, false
	}
	for _, rule := range c.rules {
		switch syscall {
		case uint64(unix.SYS_SOCKET):
			if rule.MatchesSocket(family, typ, protocol) {
				return rule, true
			}
		case uint64(unix.SYS_SOCKETPAIR):
			if rule.MatchesSocketpair(family, typ, protocol) {
				return rule, true
			}
		}
	}
	return seccomp.SocketRule{}, false
}

func (c *SocketRuleChecker) Apply(tid, tgid int, tracer syscallDenyKiller, action seccomp.OnBlockAction, nr int, rule seccomp.SocketRule, sessionID string) error {
	fc := NewFamilyCheckerWithEmitter(nil, nil)
	bf := seccomp.BlockedFamily{Family: rule.Family, Action: action, Name: rule.FamilyName}
	err := fc.Apply(tid, tgid, tracer, action, nr, bf, sessionID)
	if action == seccomp.OnBlockLog || action == seccomp.OnBlockLogAndKill {
		outcome := "denied"
		if errors.Is(err, PtraceKillRequested) {
			outcome = "killed"
		} else if err == nil && action == seccomp.OnBlockLogAndKill {
			outcome = "vanished"
		}
		c.emitSocketRuleBlocked(tid, sessionID, nr, rule, action, outcome)
	}
	return err
}

func (c *SocketRuleChecker) emitSocketRuleBlocked(tid int, sessionID string, nr int, rule seccomp.SocketRule, action seccomp.OnBlockAction, outcome string) {
	if c == nil || c.emit == nil {
		return
	}
	ev := types.Event{
		ID:        fmt.Sprintf("ptrace-socket-rule-%d-%d", tid, time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Type:      "seccomp_socket_rule_blocked",
		SessionID: sessionID,
		Source:    "ptrace",
		PID:       tid,
		Fields: map[string]any{
			"rule":            rule.Name,
			"family":          rule.FamilyName,
			"family_number":   rule.Family,
			"type":            ptraceOptionalName(rule.TypeName, rule.Type),
			"type_number":     ptraceOptionalInt(rule.Type),
			"protocol":        ptraceOptionalName(rule.ProtocolName, rule.Protocol),
			"protocol_number": ptraceOptionalInt(rule.Protocol),
			"syscall":         familySyscallName(nr),
			"action":          string(action),
			"outcome":         outcome,
			"arch":            runtime.GOARCH,
			"engine":          "ptrace",
		},
	}
	if err := c.emit.AppendEvent(context.Background(), ev); err != nil {
		slog.Warn("ptrace socket-rule: AppendEvent failed", "tid", tid, "rule", rule.Name, "error", err)
	}
	c.emit.Publish(ev)
}

func ptraceOptionalName(name string, nr *int) string {
	if nr == nil {
		return "*"
	}
	return name
}

func ptraceOptionalInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}
```

If `syscallDenyKiller` is not exported from the family checker, extract the minimal interface from `FamilyChecker.Apply` into a named package-level interface in `internal/ptrace/family_checker.go`:

```go
type syscallDenyKiller interface {
	denySyscall(tid int, errno int) error
}
```

Then update `FamilyChecker.Apply` to use that interface name for its tracer parameter.

- [ ] **Step 4: Wire checker into tracer config and dispatch**

In `internal/ptrace/tracer.go`, add to `TracerConfig`:

```go
SocketRuleChecker *SocketRuleChecker
```

In `dispatchSyscall`, before `FamilyChecker`, add:

```go
if t.cfg.SocketRuleChecker != nil &&
	(nr == unix.SYS_SOCKET || nr == unix.SYS_SOCKETPAIR) {
	family := sc.Info.Args[0]
	typ := sc.Info.Args[1]
	protocol := sc.Info.Args[2]
	if sr, ok := t.cfg.SocketRuleChecker.Check(uint64(nr), family, typ, protocol); ok {
		tgid := tid
		var sessionID string
		t.mu.Lock()
		if state := t.tracees[tid]; state != nil {
			tgid = state.TGID
			sessionID = state.SessionID
		}
		t.mu.Unlock()
		err := t.cfg.SocketRuleChecker.Apply(tid, tgid, t, sr.Action, nr, sr, sessionID)
		switch {
		case errors.Is(err, PtraceKillRequested):
			t.allowSyscall(tid)
		case errors.Is(err, ptraceAlreadyResumed):
		case err != nil:
			slog.Warn("ptrace: socket rule apply failed", "tid", tid, "rule", sr.Name, "error", err)
			t.allowSyscall(tid)
		default:
			t.allowSyscall(tid)
		}
		return
	}
}
```

- [ ] **Step 5: Resolve and install ptrace socket rules**

In `internal/api/app_ptrace_linux.go`, create:

```go
func resolveSocketRuleCheckerForPtrace(cfg *config.Config, emit ptrace.FamilyEmitter) (*ptrace.SocketRuleChecker, error) {
	if cfg == nil {
		return nil, nil
	}
	rules, err := config.ResolveSocketRules(cfg.Sandbox.Seccomp)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, nil
	}
	return ptrace.NewSocketRuleCheckerWithEmitter(rules, emit), nil
}
```

In `initPtraceTracer`, call it alongside `resolveFamilyCheckerForPtrace` and set:

```go
SocketRuleChecker: socketRuleChecker,
```

- [ ] **Step 6: Run ptrace tests**

Run: `go test ./internal/ptrace -run 'TestSocketRuleChecker|TestFamilyChecker' -v`

Expected: PASS.

Run: `go test ./internal/api -run 'TestResolveFamilyCheckerForPtrace|TestResolveSocketRuleCheckerForPtrace' -v`

Expected: PASS after adding API tests mirroring the family checker tests for non-empty and empty socket rule lists.

- [ ] **Step 7: Commit**

```bash
git add internal/ptrace/socket_rule_checker.go internal/ptrace/socket_rule_checker_test.go internal/ptrace/tracer.go internal/api/app_ptrace_linux.go internal/api/family_engine_linux.go internal/api/family_engine_linux_test.go
git commit -m "feat(ptrace): enforce socket tuple rules"
```

### Task 9: Full Verification

**Files:**
- No new files.

- [ ] **Step 1: Run focused unit and integration tests**

Run:

```bash
go test ./internal/seccomp ./internal/config ./internal/api ./internal/netmonitor/unix ./internal/ptrace -run 'SocketRule|SocketRules|dirtyfrag|SeccompFamily|FamilyChecker|mainFilterUsesUserNotify|ResolveSocketRule' -v
```

Expected: PASS, with host-capability SKIP acceptable for seccomp user-notify integration tests.

- [ ] **Step 2: Run package tests for touched areas**

Run:

```bash
go test ./internal/seccomp ./internal/config ./internal/api ./internal/netmonitor/unix ./internal/ptrace ./cmd/agentsh-unixwrap
```

Expected: PASS, with host-capability SKIP acceptable for Linux/cgo seccomp integration tests.

- [ ] **Step 3: Verify Windows compilation**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS. If Linux-only files leak types into Windows builds, add proper `//go:build linux` or non-Linux stubs instead of weakening the feature.

- [ ] **Step 4: Inspect final diff**

Run:

```bash
git diff --stat HEAD
git diff --check
```

Expected: `git diff --check` prints no whitespace errors. `git diff --stat HEAD` only shows files related to socket rules, docs, tests, and the already-approved design/plan docs.
