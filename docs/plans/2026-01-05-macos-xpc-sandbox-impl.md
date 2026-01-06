# macOS XPC Sandbox Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement XPC/Mach IPC control for macOS using sandbox profiles for blocking and audit events for monitoring.

**Architecture:** A wrapper binary (`agentsh-macwrap`) applies SBPL sandbox profiles with mach-lookup restrictions before exec. The server passes XPC configuration via environment variable. Sandbox violations are captured as audit events.

**Tech Stack:** Go, cgo (darwin sandbox.h), SBPL (Sandbox Profile Language)

---

## Task 1: Add XPC Configuration Types

**Files:**
- Modify: `internal/config/config.go`
- Create: `internal/config/xpc_test.go`

**Step 1: Write the test for XPC config parsing**

```go
// internal/config/xpc_test.go
//go:build darwin

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSandboxXPCConfig_Parse(t *testing.T) {
	yamlData := `
sandbox:
  xpc:
    enabled: true
    mode: enforce
    mach_services:
      default_action: deny
      allow:
        - "com.apple.system.logger"
      block:
        - "com.apple.security.authhost"
      allow_prefixes:
        - "com.apple.cfprefsd."
      block_prefixes:
        - "com.apple.accessibility."
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !cfg.Sandbox.XPC.Enabled {
		t.Error("xpc.enabled should be true")
	}
	if cfg.Sandbox.XPC.Mode != "enforce" {
		t.Errorf("xpc.mode = %q, want enforce", cfg.Sandbox.XPC.Mode)
	}
	if cfg.Sandbox.XPC.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", cfg.Sandbox.XPC.MachServices.DefaultAction)
	}
	if len(cfg.Sandbox.XPC.MachServices.Allow) != 1 {
		t.Errorf("allow len = %d, want 1", len(cfg.Sandbox.XPC.MachServices.Allow))
	}
	if len(cfg.Sandbox.XPC.MachServices.AllowPrefixes) != 1 {
		t.Errorf("allow_prefixes len = %d, want 1", len(cfg.Sandbox.XPC.MachServices.AllowPrefixes))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config -run TestSandboxXPCConfig_Parse -v`
Expected: FAIL (XPC field doesn't exist)

**Step 3: Add XPC config types to config.go**

Add after `SandboxSeccompConfig` (around line 266):

```go
// SandboxXPCConfig configures macOS XPC/Mach IPC control.
type SandboxXPCConfig struct {
	Enabled       bool                 `yaml:"enabled"`
	Mode          string               `yaml:"mode"` // enforce, audit, disabled
	WrapperBin    string               `yaml:"wrapper_bin"`
	MachServices  SandboxXPCMachConfig `yaml:"mach_services"`
	ESFMonitoring SandboxXPCESFConfig  `yaml:"esf_monitoring"`
}

// SandboxXPCMachConfig configures mach-lookup restrictions.
type SandboxXPCMachConfig struct {
	DefaultAction string   `yaml:"default_action"` // allow, deny
	Allow         []string `yaml:"allow"`
	Block         []string `yaml:"block"`
	AllowPrefixes []string `yaml:"allow_prefixes"`
	BlockPrefixes []string `yaml:"block_prefixes"`
}

// SandboxXPCESFConfig configures ESF-based XPC monitoring.
type SandboxXPCESFConfig struct {
	Enabled bool `yaml:"enabled"`
}
```

Add to `SandboxConfig` struct (after Seccomp field):

```go
XPC SandboxXPCConfig `yaml:"xpc"`
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config -run TestSandboxXPCConfig_Parse -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/xpc_test.go
git commit -m "feat(config): add SandboxXPCConfig for macOS XPC control"
```

---

## Task 2: Add XPC Config Defaults and Validation

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/xpc_test.go`

**Step 1: Write test for defaults**

Add to `internal/config/xpc_test.go`:

```go
func TestSandboxXPCConfig_Defaults(t *testing.T) {
	yamlData := `
sandbox:
  xpc:
    enabled: true
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	applyDefaults(&cfg)

	if cfg.Sandbox.XPC.Mode != "enforce" {
		t.Errorf("mode should default to enforce, got %q", cfg.Sandbox.XPC.Mode)
	}
	if cfg.Sandbox.XPC.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action should default to deny, got %q", cfg.Sandbox.XPC.MachServices.DefaultAction)
	}
}

func TestSandboxXPCConfig_Validation(t *testing.T) {
	yamlData := `
sandbox:
  xpc:
    enabled: true
    mode: invalid_mode
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	applyDefaults(&cfg)
	err := validateConfig(&cfg)
	if err == nil {
		t.Error("expected validation error for invalid mode")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/config -run TestSandboxXPCConfig -v`
Expected: FAIL (no defaults applied, no validation)

**Step 3: Add defaults in applyDefaultsWithSource**

Add after seccomp defaults (around line 585):

```go
// macOS XPC defaults
if cfg.Sandbox.XPC.Mode == "" {
	cfg.Sandbox.XPC.Mode = "enforce"
}
if cfg.Sandbox.XPC.MachServices.DefaultAction == "" {
	cfg.Sandbox.XPC.MachServices.DefaultAction = "deny"
}
```

**Step 4: Add validation in validateConfig**

Add after seccomp validation:

```go
// Validate XPC mode
switch cfg.Sandbox.XPC.Mode {
case "", "enforce", "audit", "disabled":
default:
	return fmt.Errorf("invalid sandbox.xpc.mode %q", cfg.Sandbox.XPC.Mode)
}
// Validate XPC default_action
switch cfg.Sandbox.XPC.MachServices.DefaultAction {
case "", "allow", "deny":
default:
	return fmt.Errorf("invalid sandbox.xpc.mach_services.default_action %q", cfg.Sandbox.XPC.MachServices.DefaultAction)
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/config -run TestSandboxXPCConfig -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/config/config.go internal/config/xpc_test.go
git commit -m "feat(config): add XPC config defaults and validation"
```

---

## Task 3: Create Default XPC Allow/Block Lists

**Files:**
- Create: `internal/api/xpc_darwin.go`
- Create: `internal/api/xpc_other.go`
- Create: `internal/api/xpc_test.go`

**Step 1: Write test for default lists**

```go
// internal/api/xpc_test.go
//go:build darwin

package api

import (
	"testing"
)

func TestDefaultXPCAllowList_NotEmpty(t *testing.T) {
	if len(DefaultXPCAllowList) == 0 {
		t.Error("DefaultXPCAllowList should not be empty")
	}
	// Check for essential service
	found := false
	for _, svc := range DefaultXPCAllowList {
		if svc == "com.apple.system.logger" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultXPCAllowList should contain com.apple.system.logger")
	}
}

func TestDefaultXPCBlockPrefixes_NotEmpty(t *testing.T) {
	if len(DefaultXPCBlockPrefixes) == 0 {
		t.Error("DefaultXPCBlockPrefixes should not be empty")
	}
	// Check for dangerous prefix
	found := false
	for _, prefix := range DefaultXPCBlockPrefixes {
		if prefix == "com.apple.accessibility." {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultXPCBlockPrefixes should contain com.apple.accessibility.")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/api -run TestDefaultXPC -v`
Expected: FAIL (variables don't exist)

**Step 3: Create xpc_darwin.go with default lists**

```go
// internal/api/xpc_darwin.go
//go:build darwin

package api

// DefaultXPCAllowList contains safe XPC services for CLI tools.
var DefaultXPCAllowList = []string{
	// Core system
	"com.apple.system.logger",
	"com.apple.system.notification_center",
	"com.apple.system.opendirectoryd",

	// CoreServices (file types, UTIs, launch services)
	"com.apple.CoreServices.coreservicesd",
	"com.apple.lsd.mapdb",
	"com.apple.lsd.modifydb",

	// Security (code signing validation)
	"com.apple.SecurityServer",
	"com.apple.securityd",

	// Preferences
	"com.apple.cfprefsd.daemon",
	"com.apple.cfprefsd.agent",

	// Fonts
	"com.apple.fonts",
	"com.apple.FontObjectsServer",

	// Distributed notifications (local only)
	"com.apple.distributed_notifications_server",
}

// DefaultXPCBlockPrefixes contains dangerous service prefixes.
var DefaultXPCBlockPrefixes = []string{
	"com.apple.accessibility.",      // Input injection, screen reading
	"com.apple.tccd.",               // TCC bypass attempts
	"com.apple.security.syspolicy.", // Security policy changes
	"com.apple.screensharing.",      // Screen sharing
	"com.apple.RemoteDesktop.",      // Remote control
}

// DefaultXPCBlockList contains specific dangerous services.
var DefaultXPCBlockList = []string{
	"com.apple.security.authhost",        // Auth dialog spoofing
	"com.apple.coreservices.appleevents", // AppleScript execution
	"com.apple.pasteboard.1",             // Clipboard exfiltration
}
```

**Step 4: Create xpc_other.go stub for non-darwin**

```go
// internal/api/xpc_other.go
//go:build !darwin

package api

// DefaultXPCAllowList is empty on non-darwin platforms.
var DefaultXPCAllowList = []string{}

// DefaultXPCBlockPrefixes is empty on non-darwin platforms.
var DefaultXPCBlockPrefixes = []string{}

// DefaultXPCBlockList is empty on non-darwin platforms.
var DefaultXPCBlockList = []string{}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/api -run TestDefaultXPC -v`
Expected: PASS

**Step 6: Verify build on linux**

Run: `go build ./internal/api`
Expected: Success (uses xpc_other.go)

**Step 7: Commit**

```bash
git add internal/api/xpc_darwin.go internal/api/xpc_other.go internal/api/xpc_test.go
git commit -m "feat(api): add default XPC allow/block lists for macOS"
```

---

## Task 4: Create macwrap Config Parsing

**Files:**
- Create: `cmd/agentsh-macwrap/config.go`
- Create: `cmd/agentsh-macwrap/config_test.go`

**Step 1: Write tests for config parsing**

```go
// cmd/agentsh-macwrap/config_test.go
//go:build darwin

package main

import (
	"os"
	"testing"
)

func TestLoadConfig_FromEnv(t *testing.T) {
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{
		"workspace_path": "/tmp/test",
		"allow_network": true,
		"mach_services": {
			"default_action": "deny",
			"allow": ["com.apple.system.logger"]
		}
	}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.WorkspacePath != "/tmp/test" {
		t.Errorf("workspace_path = %q, want /tmp/test", cfg.WorkspacePath)
	}
	if !cfg.AllowNetwork {
		t.Error("allow_network should be true")
	}
	if cfg.MachServices.DefaultAction != "deny" {
		t.Errorf("default_action = %q, want deny", cfg.MachServices.DefaultAction)
	}
	if len(cfg.MachServices.Allow) != 1 {
		t.Errorf("allow list len = %d, want 1", len(cfg.MachServices.Allow))
	}
}

func TestLoadConfig_Default(t *testing.T) {
	os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.MachServices.DefaultAction != "allow" {
		t.Errorf("default should be allow, got %q", cfg.MachServices.DefaultAction)
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{invalid}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	_, err := loadConfig()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-macwrap -run TestLoadConfig -v`
Expected: FAIL (package doesn't exist)

**Step 3: Create config.go**

```go
// cmd/agentsh-macwrap/config.go
//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is passed via AGENTSH_SANDBOX_CONFIG env var.
type WrapperConfig struct {
	WorkspacePath string             `json:"workspace_path"`
	AllowedPaths  []string           `json:"allowed_paths"`
	AllowNetwork  bool               `json:"allow_network"`
	MachServices  MachServicesConfig `json:"mach_services"`
}

// MachServicesConfig controls mach-lookup restrictions.
type MachServicesConfig struct {
	DefaultAction string   `json:"default_action"`
	Allow         []string `json:"allow"`
	Block         []string `json:"block"`
	AllowPrefixes []string `json:"allow_prefixes"`
	BlockPrefixes []string `json:"block_prefixes"`
}

// loadConfig reads wrapper config from environment.
func loadConfig() (*WrapperConfig, error) {
	val := os.Getenv("AGENTSH_SANDBOX_CONFIG")
	if val == "" {
		return &WrapperConfig{
			MachServices: MachServicesConfig{
				DefaultAction: "allow",
			},
		}, nil
	}

	var cfg WrapperConfig
	if err := json.Unmarshal([]byte(val), &cfg); err != nil {
		return nil, fmt.Errorf("parse AGENTSH_SANDBOX_CONFIG: %w", err)
	}
	return &cfg, nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./cmd/agentsh-macwrap -run TestLoadConfig -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/agentsh-macwrap/config.go cmd/agentsh-macwrap/config_test.go
git commit -m "feat(macwrap): add config parsing from environment"
```

---

## Task 5: Create macwrap Profile Generation

**Files:**
- Create: `cmd/agentsh-macwrap/profile.go`
- Create: `cmd/agentsh-macwrap/profile_test.go`

**Step 1: Write tests for profile generation**

```go
// cmd/agentsh-macwrap/profile_test.go
//go:build darwin

package main

import (
	"strings"
	"testing"
)

func TestGenerateProfile_DefaultDeny(t *testing.T) {
	cfg := &WrapperConfig{
		WorkspacePath: "/Users/test/project",
		MachServices: MachServicesConfig{
			DefaultAction: "deny",
			Allow: []string{
				"com.apple.system.logger",
				"com.apple.CoreServices.coreservicesd",
			},
			AllowPrefixes: []string{"com.apple.cfprefsd."},
		},
	}

	profile := generateProfile(cfg)

	// Should start with version
	if !strings.HasPrefix(profile, "(version 1)") {
		t.Error("profile should start with (version 1)")
	}

	// Should have deny default
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile should have (deny default)")
	}

	// Should have specific allows
	if !strings.Contains(profile, `(global-name "com.apple.system.logger")`) {
		t.Error("missing allowed service")
	}

	// Should have prefix allow
	if !strings.Contains(profile, `(global-name-prefix "com.apple.cfprefsd.")`) {
		t.Error("missing allowed prefix")
	}

	// Should have workspace
	if !strings.Contains(profile, `(subpath "/Users/test/project")`) {
		t.Error("missing workspace path")
	}

	// Should NOT have blanket allow mach-lookup
	if strings.Contains(profile, "(allow mach-lookup)") &&
		!strings.Contains(profile, "(allow mach-lookup\n") {
		t.Error("should not have blanket mach-lookup allow in deny mode")
	}
}

func TestGenerateProfile_DefaultAllow(t *testing.T) {
	cfg := &WrapperConfig{
		MachServices: MachServicesConfig{
			DefaultAction: "allow",
			Block:         []string{"com.apple.security.authhost"},
			BlockPrefixes: []string{"com.apple.accessibility."},
		},
	}

	profile := generateProfile(cfg)

	// Should have blanket allow
	if !strings.Contains(profile, "(allow mach-lookup)") {
		t.Error("should have blanket mach-lookup allow")
	}

	// Should have deny rules
	if !strings.Contains(profile, "(deny mach-lookup") {
		t.Error("missing deny rules")
	}

	if !strings.Contains(profile, `(global-name "com.apple.security.authhost")`) {
		t.Error("missing blocked service")
	}
}

func TestGenerateProfile_PathEscaping(t *testing.T) {
	cfg := &WrapperConfig{
		WorkspacePath: `/Users/test/path with "quotes"`,
		MachServices:  MachServicesConfig{DefaultAction: "allow"},
	}

	profile := generateProfile(cfg)

	if !strings.Contains(profile, `path with \"quotes\"`) {
		t.Error("quotes not properly escaped")
	}
}

func TestGenerateProfile_NetworkAllowed(t *testing.T) {
	cfg := &WrapperConfig{
		AllowNetwork: true,
		MachServices: MachServicesConfig{DefaultAction: "allow"},
	}

	profile := generateProfile(cfg)

	if !strings.Contains(profile, "(allow network*)") {
		t.Error("should allow network when AllowNetwork is true")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./cmd/agentsh-macwrap -run TestGenerateProfile -v`
Expected: FAIL (generateProfile doesn't exist)

**Step 3: Create profile.go**

```go
// cmd/agentsh-macwrap/profile.go
//go:build darwin

package main

import (
	"fmt"
	"strings"
)

// generateProfile creates an SBPL profile from config.
func generateProfile(cfg *WrapperConfig) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n\n")

	// Basic process operations
	sb.WriteString(";; Basic process operations\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow signal (target self))\n")
	sb.WriteString("(allow sysctl-read)\n\n")

	// System libraries
	sb.WriteString(";; System libraries and frameworks\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/usr/lib\")\n")
	sb.WriteString("    (subpath \"/usr/share\")\n")
	sb.WriteString("    (subpath \"/System/Library\")\n")
	sb.WriteString("    (subpath \"/Library/Frameworks\")\n")
	sb.WriteString("    (subpath \"/private/var/db/dyld\")\n")
	sb.WriteString("    (literal \"/dev/null\")\n")
	sb.WriteString("    (literal \"/dev/random\")\n")
	sb.WriteString("    (literal \"/dev/urandom\")\n")
	sb.WriteString("    (literal \"/dev/zero\"))\n\n")

	// Common tools
	sb.WriteString(";; Common tool locations\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/usr/bin\")\n")
	sb.WriteString("    (subpath \"/usr/sbin\")\n")
	sb.WriteString("    (subpath \"/bin\")\n")
	sb.WriteString("    (subpath \"/sbin\")\n")
	sb.WriteString("    (subpath \"/usr/local/bin\")\n")
	sb.WriteString("    (subpath \"/opt/homebrew/bin\")\n")
	sb.WriteString("    (subpath \"/opt/homebrew/Cellar\"))\n\n")

	// TTY access
	sb.WriteString(";; TTY access\n")
	sb.WriteString("(allow file-read* file-write*\n")
	sb.WriteString("    (regex #\"^/dev/ttys[0-9]+$\")\n")
	sb.WriteString("    (regex #\"^/dev/pty[pqrs][0-9a-f]$\")\n")
	sb.WriteString("    (literal \"/dev/tty\"))\n\n")

	// Temp files
	sb.WriteString(";; Temporary files\n")
	sb.WriteString("(allow file-read* file-write*\n")
	sb.WriteString("    (subpath \"/private/tmp\")\n")
	sb.WriteString("    (subpath \"/tmp\")\n")
	sb.WriteString("    (subpath \"/var/folders\"))\n\n")

	// Workspace
	if cfg.WorkspacePath != "" {
		sb.WriteString(";; Workspace (full access)\n")
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* file-ioctl\n    (subpath %q))\n\n",
			escapePath(cfg.WorkspacePath)))
	}

	// Additional paths
	for _, p := range cfg.AllowedPaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write*\n    (subpath %q))\n",
			escapePath(p)))
	}
	if len(cfg.AllowedPaths) > 0 {
		sb.WriteString("\n")
	}

	// Network
	if cfg.AllowNetwork {
		sb.WriteString(";; Network access\n")
		sb.WriteString("(allow network*)\n\n")
	}

	// IPC (non-mach)
	sb.WriteString(";; POSIX IPC\n")
	sb.WriteString("(allow ipc-posix*)\n\n")

	// Mach services
	sb.WriteString(";; Mach/XPC services\n")
	generateMachRules(&sb, cfg.MachServices)

	return sb.String()
}

func generateMachRules(sb *strings.Builder, cfg MachServicesConfig) {
	// Mach-register always allowed for own services
	sb.WriteString("(allow mach-register)\n\n")

	if cfg.DefaultAction == "allow" {
		// Default allow, explicit blocks
		sb.WriteString(";; Default: allow all mach-lookup\n")
		sb.WriteString("(allow mach-lookup)\n\n")

		// Block specific services
		if len(cfg.Block) > 0 || len(cfg.BlockPrefixes) > 0 {
			sb.WriteString(";; Blocked services\n")
			sb.WriteString("(deny mach-lookup\n")
			for _, svc := range cfg.Block {
				sb.WriteString(fmt.Sprintf("    (global-name %q)\n", svc))
			}
			for _, prefix := range cfg.BlockPrefixes {
				sb.WriteString(fmt.Sprintf("    (global-name-prefix %q)\n", prefix))
			}
			sb.WriteString(")\n")
		}
	} else {
		// Default deny, explicit allows
		sb.WriteString(";; Default: deny mach-lookup (allowlist mode)\n")

		// Allow specific services
		if len(cfg.Allow) > 0 || len(cfg.AllowPrefixes) > 0 {
			sb.WriteString("(allow mach-lookup\n")
			for _, svc := range cfg.Allow {
				sb.WriteString(fmt.Sprintf("    (global-name %q)\n", svc))
			}
			for _, prefix := range cfg.AllowPrefixes {
				sb.WriteString(fmt.Sprintf("    (global-name-prefix %q)\n", prefix))
			}
			sb.WriteString(")\n")
		}
	}
}

func escapePath(path string) string {
	path = strings.ReplaceAll(path, "\\", "\\\\")
	path = strings.ReplaceAll(path, "\"", "\\\"")
	return path
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./cmd/agentsh-macwrap -run TestGenerateProfile -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/agentsh-macwrap/profile.go cmd/agentsh-macwrap/profile_test.go
git commit -m "feat(macwrap): add SBPL profile generation with mach-lookup rules"
```

---

## Task 6: Create macwrap Main with cgo Sandbox

**Files:**
- Create: `cmd/agentsh-macwrap/main.go`
- Create: `cmd/agentsh-macwrap/main_test.go`

**Step 1: Write test for argument validation**

```go
// cmd/agentsh-macwrap/main_test.go
//go:build darwin

package main

import (
	"testing"
)

func TestValidateArgs_Valid(t *testing.T) {
	args := []string{"agentsh-macwrap", "--", "echo", "hello"}
	cmd, cmdArgs, err := validateArgs(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd != "echo" {
		t.Errorf("cmd = %q, want echo", cmd)
	}
	if len(cmdArgs) != 2 || cmdArgs[0] != "echo" || cmdArgs[1] != "hello" {
		t.Errorf("cmdArgs = %v, want [echo hello]", cmdArgs)
	}
}

func TestValidateArgs_MissingDash(t *testing.T) {
	args := []string{"agentsh-macwrap", "echo", "hello"}
	_, _, err := validateArgs(args)
	if err == nil {
		t.Error("expected error for missing --")
	}
}

func TestValidateArgs_NoCommand(t *testing.T) {
	args := []string{"agentsh-macwrap", "--"}
	_, _, err := validateArgs(args)
	if err == nil {
		t.Error("expected error for missing command")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/agentsh-macwrap -run TestValidateArgs -v`
Expected: FAIL (validateArgs doesn't exist)

**Step 3: Create main.go with cgo sandbox**

```go
// cmd/agentsh-macwrap/main.go
//go:build darwin

// agentsh-macwrap: applies macOS sandbox profile with XPC restrictions,
// then execs the target command.
// Usage: agentsh-macwrap -- <command> [args...]
// Requires env AGENTSH_SANDBOX_CONFIG set to JSON config.

package main

/*
#cgo LDFLAGS: -framework Foundation
#include <sandbox.h>
#include <stdlib.h>

int apply_sandbox(const char *profile, char **errorbuf) {
    return sandbox_init_with_parameters(profile, 0, NULL, errorbuf);
}

void free_error(char *errorbuf) {
    sandbox_free_error(errorbuf);
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	log.SetFlags(0)

	cmd, args, err := validateArgs(os.Args)
	if err != nil {
		log.Fatalf("usage: %s -- <command> [args...]\nerror: %v", os.Args[0], err)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	profile := generateProfile(cfg)

	if err := applySandbox(profile); err != nil {
		log.Fatalf("apply sandbox: %v", err)
	}

	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}

// validateArgs parses and validates command line arguments.
func validateArgs(args []string) (cmd string, cmdArgs []string, err error) {
	if len(args) < 3 {
		return "", nil, fmt.Errorf("not enough arguments")
	}
	if args[1] != "--" {
		return "", nil, fmt.Errorf("missing -- separator")
	}
	return args[2], args[2:], nil
}

// applySandbox applies the SBPL profile using sandbox_init.
func applySandbox(profile string) error {
	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	var errorbuf *C.char
	rc := C.apply_sandbox(cProfile, &errorbuf)
	if rc != 0 {
		var errMsg string
		if errorbuf != nil {
			errMsg = C.GoString(errorbuf)
			C.free_error(errorbuf)
		}
		return fmt.Errorf("sandbox_init failed (rc=%d): %s", rc, errMsg)
	}
	return nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./cmd/agentsh-macwrap -run TestValidateArgs -v`
Expected: PASS

**Step 5: Build the binary (darwin only)**

Run: `GOOS=darwin go build -o /dev/null ./cmd/agentsh-macwrap 2>&1 || echo "Expected: build requires darwin"`
Expected: Fails on Linux (cgo darwin headers), succeeds on macOS

**Step 6: Commit**

```bash
git add cmd/agentsh-macwrap/main.go cmd/agentsh-macwrap/main_test.go
git commit -m "feat(macwrap): add main with cgo sandbox_init"
```

---

## Task 7: Add XPC Audit Event Types

**Files:**
- Modify: `internal/events/schema.go`

**Step 1: Add XPC event types**

Add at the end of `internal/events/schema.go`:

```go
// XPCConnectEvent - XPC/Mach service connection attempt (macOS).
// Captured via ES_EVENT_TYPE_NOTIFY_XPC_CONNECT (macOS 14+) or sandbox violation logs.
type XPCConnectEvent struct {
	BaseEvent

	// Process info
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Comm      string `json:"comm"`
	Exe       string `json:"exe"`
	SigningID string `json:"signing_id,omitempty"`

	// XPC connection details
	ServiceName   string `json:"service_name"`
	ServiceDomain string `json:"service_domain,omitempty"` // system, user, per-pid

	// Decision
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"` // allowlist, blocklist, default_allow, default_deny

	// For blocked connections
	BlockedBy string `json:"blocked_by,omitempty"` // sandbox_profile, esf_policy

	// Source of detection
	Source string `json:"source"` // esf, sandbox_log
}

// XPCSandboxViolationEvent - Sandbox denied mach-lookup (from system.log).
type XPCSandboxViolationEvent struct {
	BaseEvent

	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	ServiceName string `json:"service_name"`
	Operation   string `json:"operation"` // mach-lookup, mach-register
	Profile     string `json:"profile,omitempty"`
}
```

**Step 2: Verify build**

Run: `go build ./internal/events`
Expected: Success

**Step 3: Commit**

```bash
git add internal/events/schema.go
git commit -m "feat(events): add XPCConnectEvent and XPCSandboxViolationEvent"
```

---

## Task 8: Add Server-Side macOS Sandbox Wrapper Integration

**Files:**
- Modify: `internal/api/core.go`

**Step 1: Add wrapper config type and wrapWithMacSandbox function**

Add after `seccompWrapperConfig` (around line 30):

```go
// macSandboxWrapperConfig is passed to agentsh-macwrap via
// AGENTSH_SANDBOX_CONFIG environment variable.
type macSandboxWrapperConfig struct {
	WorkspacePath string                       `json:"workspace_path"`
	AllowedPaths  []string                     `json:"allowed_paths"`
	AllowNetwork  bool                         `json:"allow_network"`
	MachServices  macSandboxMachServicesConfig `json:"mach_services"`
}

type macSandboxMachServicesConfig struct {
	DefaultAction string   `json:"default_action"`
	Allow         []string `json:"allow"`
	Block         []string `json:"block"`
	AllowPrefixes []string `json:"allow_prefixes"`
	BlockPrefixes []string `json:"block_prefixes"`
}
```

Add the wrapper function (add after the unix socket wrapping block, around line 580):

```go
// wrapWithMacSandbox wraps command with agentsh-macwrap for XPC control.
func (a *App) wrapWithMacSandbox(
	req *types.ExecRequest,
	origCommand string,
	origArgs []string,
	sess *session.Session,
) {
	wrapperBin := strings.TrimSpace(a.cfg.Sandbox.XPC.WrapperBin)
	if wrapperBin == "" {
		wrapperBin = "agentsh-macwrap"
	}

	// Check if wrapper exists
	if _, err := exec.LookPath(wrapperBin); err != nil {
		a.logger.Debug("macwrap not found, skipping sandbox", "wrapper", wrapperBin)
		return
	}

	// Build mach services config with defaults
	machCfg := macSandboxMachServicesConfig{
		DefaultAction: a.cfg.Sandbox.XPC.MachServices.DefaultAction,
		Allow:         a.cfg.Sandbox.XPC.MachServices.Allow,
		Block:         a.cfg.Sandbox.XPC.MachServices.Block,
		AllowPrefixes: a.cfg.Sandbox.XPC.MachServices.AllowPrefixes,
		BlockPrefixes: a.cfg.Sandbox.XPC.MachServices.BlockPrefixes,
	}

	// Apply defaults if not configured
	if machCfg.DefaultAction == "" {
		machCfg.DefaultAction = "deny"
	}
	if len(machCfg.Allow) == 0 && machCfg.DefaultAction == "deny" {
		machCfg.Allow = DefaultXPCAllowList
	}
	if len(machCfg.BlockPrefixes) == 0 && machCfg.DefaultAction == "allow" {
		machCfg.BlockPrefixes = DefaultXPCBlockPrefixes
	}

	cfg := macSandboxWrapperConfig{
		WorkspacePath: sess.WorkspacePath(),
		AllowedPaths:  []string{os.Getenv("HOME")},
		AllowNetwork:  true, // Default allow, can be policy-controlled
		MachServices:  machCfg,
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		a.logger.Error("failed to marshal mac sandbox config", "error", err)
		return
	}

	if req.Env == nil {
		req.Env = map[string]string{}
	}
	req.Env["AGENTSH_SANDBOX_CONFIG"] = string(cfgJSON)
	req.Command = wrapperBin
	req.Args = append([]string{"--", origCommand}, origArgs...)
}
```

**Step 2: Add import for exec and runtime**

At the top of the file, ensure these imports exist:

```go
import (
	// ... existing imports ...
	"os/exec"
	"runtime"
)
```

**Step 3: Wire up in handleExec**

Find the exec handling code (around line 580 after unix socket wrapping) and add:

```go
// macOS: sandbox wrapper with XPC control
if runtime.GOOS == "darwin" && a.cfg.Sandbox.XPC.Enabled && a.cfg.Sandbox.XPC.Mode == "enforce" {
	a.wrapWithMacSandbox(&wrappedReq, origCommand, origArgs, sess)
}
```

**Step 4: Verify build**

Run: `go build ./internal/api`
Expected: Success

**Step 5: Commit**

```bash
git add internal/api/core.go
git commit -m "feat(api): add wrapWithMacSandbox for XPC sandbox integration"
```

---

## Task 9: Add Build Target for macwrap

**Files:**
- Modify: `Makefile` or `.goreleaser.yml`

**Step 1: Check existing build setup**

Run: `ls Makefile .goreleaser.yml 2>/dev/null`

**Step 2: Add macwrap to build targets**

If using Makefile, add:

```makefile
build-macwrap:
	GOOS=darwin go build -o bin/agentsh-macwrap ./cmd/agentsh-macwrap
```

If using goreleaser, add to builds section:

```yaml
  - id: agentsh-macwrap
    main: ./cmd/agentsh-macwrap
    binary: agentsh-macwrap
    goos:
      - darwin
    goarch:
      - amd64
      - arm64
    env:
      - CGO_ENABLED=1
```

**Step 3: Commit**

```bash
git add Makefile .goreleaser.yml
git commit -m "build: add agentsh-macwrap build target"
```

---

## Task 10: Add Documentation

**Files:**
- Create: `docs/macos-xpc-sandbox.md`
- Modify: `docs/cross-platform.md` (if exists)

**Step 1: Create XPC sandbox documentation**

```markdown
# macOS XPC Sandbox

agentsh provides XPC/Mach IPC control on macOS through sandbox profiles that restrict which system services sandboxed processes can communicate with.

## Overview

XPC (Cross-Process Communication) is macOS's primary IPC mechanism. By default, any process can connect to any XPC service. agentsh's XPC sandbox restricts this using Apple's sandbox profile system.

## Configuration

```yaml
sandbox:
  xpc:
    enabled: true
    mode: enforce  # enforce | audit | disabled
    mach_services:
      default_action: deny  # deny (allowlist) or allow (blocklist)
      allow:
        - "com.apple.system.logger"
        - "com.apple.CoreServices.coreservicesd"
      block:
        - "com.apple.security.authhost"
      allow_prefixes:
        - "com.apple.cfprefsd."
      block_prefixes:
        - "com.apple.accessibility."
```

## How It Works

1. When `agentsh exec` runs a command on macOS with XPC enabled, it wraps the command with `agentsh-macwrap`
2. The wrapper generates an SBPL (Sandbox Profile Language) profile with mach-lookup rules
3. The sandbox is applied via `sandbox_init_with_parameters()` before exec
4. The sandboxed process can only connect to allowed XPC services

## Default Allow List

When `default_action: deny`, these services are allowed by default:
- `com.apple.system.logger` - System logging
- `com.apple.CoreServices.coreservicesd` - Core services
- `com.apple.lsd.mapdb` - Launch services
- `com.apple.SecurityServer` - Code signing
- `com.apple.cfprefsd.*` - Preferences

## Default Block List

When `default_action: allow`, these are blocked by default:
- `com.apple.accessibility.*` - Accessibility APIs (input injection)
- `com.apple.tccd.*` - TCC bypass attempts
- `com.apple.security.authhost` - Auth dialog spoofing
- `com.apple.coreservices.appleevents` - AppleScript

## Discovering Required Services

To find which XPC services your application needs:

```bash
# Trace sandbox violations
sandbox-exec -t /tmp/trace.out -p "(version 1)(deny default)(allow mach-lookup)" ./myapp

# Watch system log
log stream --predicate 'subsystem == "com.apple.sandbox"' --level debug
```

## Audit Events

XPC sandbox violations generate `xpc_sandbox_violation` events in the audit log.
```

**Step 2: Commit**

```bash
git add docs/macos-xpc-sandbox.md
git commit -m "docs: add macOS XPC sandbox documentation"
```

---

## Task 11: Final Verification

**Step 1: Run all tests**

Run: `go test ./... -v`
Expected: All tests pass

**Step 2: Build all binaries**

Run: `go build ./...`
Expected: Success

**Step 3: Verify config loading**

Run: `go test ./internal/config -v`
Expected: All tests pass including XPC tests

**Step 4: Update design status**

Edit `docs/plans/2026-01-04-macos-xpc-sandbox-design.md` and change:
```
**Status:** Approved
```
to:
```
**Status:** Implemented
```

**Step 5: Final commit**

```bash
git add docs/plans/2026-01-04-macos-xpc-sandbox-design.md
git commit -m "docs: mark XPC sandbox design as implemented"
```

---

## Summary

| Task | Component | Files |
|------|-----------|-------|
| 1 | XPC Config Types | `internal/config/config.go` |
| 2 | Config Defaults/Validation | `internal/config/config.go` |
| 3 | Default XPC Lists | `internal/api/xpc_darwin.go` |
| 4 | macwrap Config | `cmd/agentsh-macwrap/config.go` |
| 5 | macwrap Profile Gen | `cmd/agentsh-macwrap/profile.go` |
| 6 | macwrap Main | `cmd/agentsh-macwrap/main.go` |
| 7 | Audit Events | `internal/events/schema.go` |
| 8 | Server Integration | `internal/api/core.go` |
| 9 | Build Target | `Makefile`/`.goreleaser.yml` |
| 10 | Documentation | `docs/macos-xpc-sandbox.md` |
| 11 | Final Verification | All |

**Note:** ESF monitoring (Phase 5 from design) is deferred as it requires Apple entitlements. The sandbox-based enforcement works without entitlements.
