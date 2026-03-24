# Dynamic Seatbelt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace static blanket-allow seatbelt profiles with policy-driven SBPL generation, extension tokens, and Mach service restriction on macOS.

**Architecture:** Three new packages (`sbpl/`, `sandboxext/`), one enhanced server method (`wrapWithMacSandbox`), and updated macwrap consumer. Profile generation moves from macwrap to the server where the policy engine lives. Macwrap becomes a thin applier: consume tokens, apply compiled profile, exec.

**Tech Stack:** Go, CGo (sandbox extension API), SBPL (Sandbox Profile Language), Apple private sandbox API

**Spec:** `docs/superpowers/specs/2026-03-23-dynamic-seatbelt-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/platform/darwin/sbpl/builder.go` | New — typed SBPL profile builder, no CGo |
| `internal/platform/darwin/sbpl/builder_test.go` | New — builder unit tests (pure Go, any OS) |
| `internal/platform/darwin/sandboxext/manager.go` | New — CGo wrapper for sandbox extension token API |
| `internal/platform/darwin/sandboxext/manager_test.go` | New — token manager tests (darwin-only) |
| `internal/platform/darwin/sandbox.go` | Modify — add `CompileDarwinSandbox()` orchestrator |
| `internal/platform/darwin/sandbox_test.go` | New — compilation integration tests (darwin-only) |
| `internal/api/core.go` | Modify — update `wrapWithMacSandbox()` to use compiled profiles |
| `cmd/agentsh-macwrap/config.go` | Modify — add `CompiledProfile`, `ExtensionTokens` fields |
| `cmd/agentsh-macwrap/main.go` | Modify — add `consumeTokens()`, use compiled profile |
| `cmd/agentsh-macwrap/profile.go` | Unchanged — kept as legacy fallback |
| `internal/capabilities/detect_darwin.go` | Modify — add dynamic seatbelt tiers |

---

### Task 1: SBPL Builder — Core Types and File Rules

**Files:**
- Create: `internal/platform/darwin/sbpl/builder.go`
- Create: `internal/platform/darwin/sbpl/builder_test.go`

- [ ] **Step 1: Write failing tests for core types and file read rules**

Create `internal/platform/darwin/sbpl/builder_test.go`:

```go
package sbpl

import (
	"strings"
	"testing"
)

func TestNew_ProducesValidEmptyProfile(t *testing.T) {
	p := New()
	got, err := p.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.HasPrefix(got, "(version 1)") {
		t.Errorf("profile should start with (version 1), got: %s", got[:40])
	}
	if !strings.Contains(got, "(deny default)") {
		t.Error("profile should contain (deny default)")
	}
}

func TestAllowFileRead_Subpath(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, "/usr/lib")
	got, err := p.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(got, `(allow file-read* (subpath "/usr/lib"))`) {
		t.Errorf("missing file-read subpath rule in:\n%s", got)
	}
}

func TestAllowFileRead_Literal(t *testing.T) {
	p := New()
	p.AllowFileRead(Literal, "/etc/hosts")
	got, err := p.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(got, `(allow file-read* (literal "/etc/hosts"))`) {
		t.Errorf("missing file-read literal rule in:\n%s", got)
	}
}

func TestAllowFileReadWrite_Subpath(t *testing.T) {
	p := New()
	p.AllowFileReadWrite(Subpath, "/workspace/project")
	got, err := p.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(got, `(allow file-read* file-write* (subpath "/workspace/project"))`) {
		t.Errorf("missing file-read-write subpath rule in:\n%s", got)
	}
}

func TestBuild_RejectsRelativePath(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, "relative/path")
	_, err := p.Build()
	if err == nil {
		t.Error("expected error for relative path")
	}
}

func TestBuild_EscapesQuotesInPaths(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, `/Users/test/path with "quotes"`)
	got, err := p.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(got, `path with \"quotes\"`) {
		t.Errorf("quotes not escaped in:\n%s", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/darwin/sbpl/... -v`
Expected: compilation error — package doesn't exist yet.

- [ ] **Step 3: Implement core types and file rule methods**

Create `internal/platform/darwin/sbpl/builder.go`:

```go
package sbpl

import (
	"fmt"
	"strings"
)

// PathMatch specifies how a path is matched in SBPL.
type PathMatch int

const (
	Literal PathMatch = iota // (literal "/exact/path")
	Subpath                  // (subpath "/dir")
	Regex                    // (regex #"/pattern"#)
)

// ruleKind groups rules for ordering (deny before allow per category).
type ruleKind int

const (
	kindFileAllow ruleKind = iota
	kindFileDeny
	kindExecAllow
	kindExecDeny
	kindMachAllow
	kindMachDeny
	kindNetworkAllow
	kindNetworkDeny
	kindOther
)

type rule struct {
	kind ruleKind
	sbpl string
}

// Profile builds an SBPL sandbox profile.
type Profile struct {
	rules []rule
}

// New creates a new Profile with (version 1) and (deny default).
func New() *Profile {
	return &Profile{}
}

// AllowFileRead adds a file-read* allow rule.
func (p *Profile) AllowFileRead(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* (%s %s))", matchStr(match), quotePath(path)),
	})
}

// AllowFileReadWrite adds a file-read* file-write* allow rule.
func (p *Profile) AllowFileReadWrite(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* (%s %s))", matchStr(match), quotePath(path)),
	})
}

// AllowFileReadWriteIOctl adds a file-read* file-write* file-ioctl allow rule (for workspace).
func (p *Profile) AllowFileReadWriteIOctl(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* file-ioctl (%s %s))", matchStr(match), quotePath(path)),
	})
}

// Build produces the complete SBPL profile string.
func (p *Profile) Build() (string, error) {
	// Validate all rules
	for _, r := range p.rules {
		if err := validateRule(r); err != nil {
			return "", err
		}
	}

	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n\n")

	// Emit deny rules before allow rules within each category for readability.
	// SBPL deny rules override allow rules regardless of order, but this makes
	// the profile easier to read and audit.
	var denyRules, allowRules []rule
	for _, r := range p.rules {
		switch r.kind {
		case kindFileDeny, kindExecDeny, kindMachDeny, kindNetworkDeny:
			denyRules = append(denyRules, r)
		default:
			allowRules = append(allowRules, r)
		}
	}

	if len(denyRules) > 0 {
		for _, r := range denyRules {
			sb.WriteString(r.sbpl)
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	for _, r := range allowRules {
		sb.WriteString(r.sbpl)
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func matchStr(m PathMatch) string {
	switch m {
	case Literal:
		return "literal"
	case Subpath:
		return "subpath"
	case Regex:
		return "regex"
	default:
		return "literal"
	}
}

func quotePath(path string) string {
	if strings.HasPrefix(path, "#\"") {
		// Already a regex pattern
		return path
	}
	escaped := strings.ReplaceAll(path, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	return fmt.Sprintf("%q", escaped)
}

func validateRule(r rule) error {
	// Extract path from the SBPL string for validation
	// Rules with regex paths use #"..."# syntax and don't need absolute path check
	sbpl := r.sbpl
	if strings.Contains(sbpl, "regex") {
		return nil
	}

	// Find quoted path in the rule
	// Format: (allow/deny ... (literal/subpath "path"))
	start := strings.LastIndex(sbpl, `"`)
	if start == -1 {
		return nil // no path to validate
	}
	// Find the opening quote
	pathEnd := start
	pathStart := strings.LastIndex(sbpl[:pathEnd], `"`)
	if pathStart == -1 {
		return nil
	}

	path := sbpl[pathStart+1 : pathEnd]
	// Unescape for validation
	path = strings.ReplaceAll(path, "\\\"", "\"")
	path = strings.ReplaceAll(path, "\\\\", "\\")

	if path != "" && !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sbpl: path must be absolute, got %q", path)
	}
	return nil
}
```

Note: the `quotePath` function double-escapes because `fmt.Sprintf("%q", ...)` adds its own escaping. We need to handle this more carefully. Let me fix that:

Replace the `quotePath` function with:

```go
func quotePath(path string) string {
	if strings.HasPrefix(path, `#"`) {
		// Already a regex pattern like #"^/dev/ttys[0-9]+$"#
		return path
	}
	escaped := strings.ReplaceAll(path, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}
```

And update `validateRule` to properly extract the path:

```go
func validateRule(r rule) error {
	sbpl := r.sbpl
	if strings.Contains(sbpl, "regex") {
		return nil
	}
	// Extract path between the last pair of quotes
	lastClose := strings.LastIndex(sbpl, `"`)
	if lastClose <= 0 {
		return nil
	}
	// Search backward from lastClose-1 for the opening quote
	sub := sbpl[:lastClose]
	lastOpen := strings.LastIndex(sub, `"`)
	if lastOpen == -1 {
		return nil
	}
	path := sbpl[lastOpen+1 : lastClose]
	path = strings.ReplaceAll(path, `\"`, `"`)
	path = strings.ReplaceAll(path, `\\`, `\`)

	if path != "" && !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sbpl: path must be absolute, got %q", path)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/darwin/sbpl/... -v`
Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/sbpl/
git commit -m "feat(sbpl): add SBPL builder with file rule support"
```

---

### Task 2: SBPL Builder — Exec, Mach, and Network Rules

**Files:**
- Modify: `internal/platform/darwin/sbpl/builder.go`
- Modify: `internal/platform/darwin/sbpl/builder_test.go`

- [ ] **Step 1: Write failing tests for exec, Mach, and network rules**

Add to `builder_test.go`:

```go
func TestAllowProcessExec_Subpath(t *testing.T) {
	p := New()
	p.AllowProcessExec(Subpath, "/usr/bin")
	got, _ := p.Build()
	if !strings.Contains(got, `(allow process-exec (subpath "/usr/bin"))`) {
		t.Errorf("missing exec subpath rule in:\n%s", got)
	}
}

func TestDenyProcessExec_Literal(t *testing.T) {
	p := New()
	p.DenyProcessExec(Literal, "/usr/bin/osascript")
	got, _ := p.Build()
	if !strings.Contains(got, `(deny process-exec (literal "/usr/bin/osascript"))`) {
		t.Errorf("missing exec deny rule in:\n%s", got)
	}
}

func TestDenyBeforeAllow_Ordering(t *testing.T) {
	p := New()
	p.AllowProcessExec(Subpath, "/usr/bin")
	p.DenyProcessExec(Literal, "/usr/bin/osascript")
	got, _ := p.Build()
	denyIdx := strings.Index(got, "(deny process-exec")
	allowIdx := strings.Index(got, "(allow process-exec")
	if denyIdx == -1 || allowIdx == -1 {
		t.Fatalf("missing rules in:\n%s", got)
	}
	if denyIdx > allowIdx {
		t.Error("deny rules should be emitted before allow rules")
	}
}

func TestAllowMachLookup(t *testing.T) {
	p := New()
	p.AllowMachLookup("com.apple.system.logger")
	got, _ := p.Build()
	if !strings.Contains(got, `(allow mach-lookup (global-name "com.apple.system.logger"))`) {
		t.Errorf("missing mach-lookup rule in:\n%s", got)
	}
}

func TestAllowMachLookupPrefix(t *testing.T) {
	p := New()
	p.AllowMachLookupPrefix("com.apple.system.")
	got, _ := p.Build()
	if !strings.Contains(got, `(allow mach-lookup (global-name-prefix "com.apple.system."))`) {
		t.Errorf("missing mach-lookup prefix rule in:\n%s", got)
	}
}

func TestDenyMachLookup(t *testing.T) {
	p := New()
	p.DenyMachLookup("com.apple.security.authtrampoline")
	got, _ := p.Build()
	if !strings.Contains(got, `(deny mach-lookup (global-name "com.apple.security.authtrampoline"))`) {
		t.Errorf("missing mach deny rule in:\n%s", got)
	}
}

func TestAllowNetworkAll(t *testing.T) {
	p := New()
	p.AllowNetworkAll()
	got, _ := p.Build()
	if !strings.Contains(got, "(allow network*)") {
		t.Errorf("missing network allow-all in:\n%s", got)
	}
}

func TestAllowNetworkOutbound(t *testing.T) {
	p := New()
	p.AllowNetworkOutbound("tcp", "*:443")
	got, _ := p.Build()
	if !strings.Contains(got, `(allow network-outbound (remote tcp "*:443"))`) {
		t.Errorf("missing network outbound rule in:\n%s", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/darwin/sbpl/... -v -run 'TestAllow(Process|Mach|Network)|TestDeny'`
Expected: compilation errors for undefined methods.

- [ ] **Step 3: Add exec, Mach, and network methods to builder.go**

Add to `builder.go`:

```go
// AllowProcessExec adds a process-exec allow rule.
func (p *Profile) AllowProcessExec(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindExecAllow,
		sbpl: fmt.Sprintf("(allow process-exec (%s %s))", matchStr(match), quotePath(path)),
	})
}

// DenyProcessExec adds a process-exec deny rule.
func (p *Profile) DenyProcessExec(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindExecDeny,
		sbpl: fmt.Sprintf("(deny process-exec (%s %s))", matchStr(match), quotePath(path)),
	})
}

// AllowMachLookup allows lookup of a specific Mach service.
func (p *Profile) AllowMachLookup(serviceName string) {
	p.rules = append(p.rules, rule{
		kind: kindMachAllow,
		sbpl: fmt.Sprintf("(allow mach-lookup (global-name %q))", serviceName),
	})
}

// AllowMachLookupPrefix allows lookup of Mach services by prefix.
func (p *Profile) AllowMachLookupPrefix(prefix string) {
	p.rules = append(p.rules, rule{
		kind: kindMachAllow,
		sbpl: fmt.Sprintf("(allow mach-lookup (global-name-prefix %q))", prefix),
	})
}

// DenyMachLookup denies lookup of a specific Mach service.
func (p *Profile) DenyMachLookup(serviceName string) {
	p.rules = append(p.rules, rule{
		kind: kindMachDeny,
		sbpl: fmt.Sprintf("(deny mach-lookup (global-name %q))", serviceName),
	})
}

// AllowNetworkAll allows all network operations.
func (p *Profile) AllowNetworkAll() {
	p.rules = append(p.rules, rule{
		kind: kindNetworkAllow,
		sbpl: "(allow network*)",
	})
}

// AllowNetworkOutbound allows outbound connections on a specific protocol/port.
// Note: port-level filtering has limited reliability on macOS 12+.
func (p *Profile) AllowNetworkOutbound(proto, hostPort string) {
	p.rules = append(p.rules, rule{
		kind: kindNetworkAllow,
		sbpl: fmt.Sprintf(`(allow network-outbound (remote %s "%s"))`, proto, hostPort),
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/darwin/sbpl/... -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/sbpl/
git commit -m "feat(sbpl): add exec, mach-lookup, and network rule methods"
```

---

### Task 3: SBPL Builder — System Essentials

**Files:**
- Modify: `internal/platform/darwin/sbpl/builder.go`
- Modify: `internal/platform/darwin/sbpl/builder_test.go`

- [ ] **Step 1: Write failing test for AllowSystemEssentials**

Add to `builder_test.go`:

```go
func TestAllowSystemEssentials_ContainsRequiredPaths(t *testing.T) {
	p := New()
	p.AllowSystemEssentials()
	got, err := p.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	required := []string{
		// Dev files
		`(literal "/dev/null")`,
		`(literal "/dev/random")`,
		`(literal "/dev/urandom")`,
		`(literal "/dev/zero")`,
		// System libraries
		`(subpath "/usr/lib")`,
		`(subpath "/usr/share")`,
		`(subpath "/System/Library")`,
		`(subpath "/Library/Frameworks")`,
		`(subpath "/private/var/db/dyld")`,
		// Process ops
		"(allow process-fork)",
		"(allow signal (target self))",
		"(allow sysctl-read)",
		// TTY
		`(literal "/dev/tty")`,
		// Common tool paths (read-only)
		`(subpath "/usr/bin")`,
		`(subpath "/usr/sbin")`,
		`(subpath "/bin")`,
		`(subpath "/sbin")`,
		`(subpath "/usr/local/bin")`,
		`(subpath "/opt/homebrew/bin")`,
		`(subpath "/opt/homebrew/Cellar")`,
		// Temp
		`(subpath "/tmp")`,
		`(subpath "/private/tmp")`,
		`(subpath "/var/folders")`,
		// IPC
		"(allow ipc-posix*)",
		"(allow mach-register)",
	}

	for _, s := range required {
		if !strings.Contains(got, s) {
			t.Errorf("AllowSystemEssentials missing: %s", s)
		}
	}
}

func TestAllowSystemEssentials_ContainsTTYRegex(t *testing.T) {
	p := New()
	p.AllowSystemEssentials()
	got, _ := p.Build()
	if !strings.Contains(got, `^/dev/ttys[0-9]+$`) {
		t.Error("missing TTY regex pattern")
	}
	if !strings.Contains(got, `^/dev/pty[pqrs][0-9a-f]$`) {
		t.Error("missing PTY regex pattern")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/darwin/sbpl/... -v -run TestAllowSystemEssentials`
Expected: FAIL — `AllowSystemEssentials` not defined.

- [ ] **Step 3: Implement AllowSystemEssentials**

Add to `builder.go`:

```go
// AllowSystemEssentials adds all rules needed for basic process operation.
// Mirrors the paths in cmd/agentsh-macwrap/profile.go generateProfile().
func (p *Profile) AllowSystemEssentials() {
	// Process operations
	p.rules = append(p.rules,
		rule{kind: kindOther, sbpl: "(allow process-fork)"},
		rule{kind: kindOther, sbpl: "(allow signal (target self))"},
		rule{kind: kindOther, sbpl: "(allow sysctl-read)"},
	)

	// Dev files + system libraries (combined file-read* rule)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/usr/lib\")\n" +
			"    (subpath \"/usr/share\")\n" +
			"    (subpath \"/System/Library\")\n" +
			"    (subpath \"/Library/Frameworks\")\n" +
			"    (subpath \"/private/var/db/dyld\")\n" +
			"    (literal \"/dev/null\")\n" +
			"    (literal \"/dev/random\")\n" +
			"    (literal \"/dev/urandom\")\n" +
			"    (literal \"/dev/zero\"))",
	})

	// Common tool paths (read-only)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/usr/bin\")\n" +
			"    (subpath \"/usr/sbin\")\n" +
			"    (subpath \"/bin\")\n" +
			"    (subpath \"/sbin\")\n" +
			"    (subpath \"/usr/local/bin\")\n" +
			"    (subpath \"/opt/homebrew/bin\")\n" +
			"    (subpath \"/opt/homebrew/Cellar\"))",
	})

	// TTY access
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (regex #\"^/dev/ttys[0-9]+$\"#)\n" +
			"    (regex #\"^/dev/pty[pqrs][0-9a-f]$\"#)\n" +
			"    (literal \"/dev/tty\"))",
	})

	// Temp files
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (subpath \"/private/tmp\")\n" +
			"    (subpath \"/tmp\")\n" +
			"    (subpath \"/var/folders\"))",
	})

	// IPC
	p.rules = append(p.rules,
		rule{kind: kindOther, sbpl: "(allow ipc-posix*)"},
		rule{kind: kindOther, sbpl: "(allow mach-register)"},
	)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/darwin/sbpl/... -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/sbpl/
git commit -m "feat(sbpl): add AllowSystemEssentials with all required paths"
```

---

### Task 4: Extension Token Manager

**Files:**
- Create: `internal/platform/darwin/sandboxext/manager.go`
- Create: `internal/platform/darwin/sandboxext/manager_test.go`

Note: This package requires CGo and darwin. Tests will only run on macOS. The `sandbox_extension_issue_file` and `sandbox_extension_consume` functions are from the private sandbox API — they work without entitlements when called from an unsandboxed process.

- [ ] **Step 1: Write failing tests**

Create `internal/platform/darwin/sandboxext/manager_test.go`:

```go
//go:build darwin && cgo

package sandboxext

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIssue_ReturnsToken(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	// Create a real temp file to issue a token for
	dir := t.TempDir()
	tok, err := mgr.Issue(dir, ReadWrite)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.Value == "" {
		t.Error("token value should not be empty")
	}
	if tok.Path != dir {
		t.Errorf("token path = %q, want %q", tok.Path, dir)
	}
	if tok.Class != ReadWrite {
		t.Errorf("token class = %q, want %q", tok.Class, ReadWrite)
	}
}

func TestActiveTokens_ReturnsIssuedTokens(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	dir := t.TempDir()
	mgr.Issue(dir, ReadOnly)

	tokens := mgr.ActiveTokens()
	if len(tokens) != 1 {
		t.Fatalf("ActiveTokens len = %d, want 1", len(tokens))
	}
	if tokens[0].Path != dir {
		t.Errorf("token path = %q, want %q", tokens[0].Path, dir)
	}
}

func TestRevoke_RemovesToken(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	dir := t.TempDir()
	mgr.Issue(dir, ReadOnly)

	if err := mgr.Revoke(dir); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(mgr.ActiveTokens()) != 0 {
		t.Error("token should be removed after revoke")
	}
}

func TestRevokeAll_ClearsAll(t *testing.T) {
	mgr := NewManager()

	d1 := t.TempDir()
	d2 := t.TempDir()
	mgr.Issue(d1, ReadOnly)
	mgr.Issue(d2, ReadWrite)

	mgr.RevokeAll()
	if len(mgr.ActiveTokens()) != 0 {
		t.Error("all tokens should be cleared")
	}
}

func TestRevoke_DoubleRevoke_NoError(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	dir := t.TempDir()
	mgr.Issue(dir, ReadOnly)
	mgr.Revoke(dir)

	// Second revoke should not error
	if err := mgr.Revoke(dir); err != nil {
		t.Errorf("double revoke should not error, got: %v", err)
	}
}

func TestIssue_NonexistentPath(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	_, err := mgr.Issue("/nonexistent/path/that/does/not/exist", ReadOnly)
	// sandbox_extension_issue may succeed for nonexistent paths (it issues a token
	// for the capability, not the file). If it errors, that's also acceptable.
	// This test just documents the behavior.
	if err != nil {
		t.Logf("Issue for nonexistent path returned error (acceptable): %v", err)
	}
}

func TestConsumeToken_ValidToken(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	dir := t.TempDir()
	// Create a file to verify access
	testFile := filepath.Join(dir, "test.txt")
	os.WriteFile(testFile, []byte("hello"), 0644)

	tok, err := mgr.Issue(dir, ReadOnly)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Consume should succeed
	handle, err := ConsumeToken(tok.Value)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if handle < 0 {
		t.Errorf("handle should be >= 0, got %d", handle)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/darwin/sandboxext/... -v`
Expected: compilation error — package doesn't exist.

- [ ] **Step 3: Implement the token manager**

Create `internal/platform/darwin/sandboxext/manager.go`:

```go
//go:build darwin && cgo

package sandboxext

/*
#include <sandbox.h>
#include <stdlib.h>

// sandbox_extension_issue_file is a private API for issuing sandbox extension tokens.
extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

// sandbox_extension_consume consumes a token, granting the calling process access.
extern int64_t sandbox_extension_consume(const char *token);

// sandbox_extension_release releases a previously consumed extension.
extern int sandbox_extension_release(int64_t handle);
*/
import "C"

import (
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// ExtClass represents a sandbox extension class.
type ExtClass string

const (
	ReadOnly  ExtClass = "com.apple.app-sandbox.read"
	ReadWrite ExtClass = "com.apple.app-sandbox.read-write"
)

// Token represents an issued sandbox extension token.
type Token struct {
	Path   string
	Class  ExtClass
	Value  string // opaque token string from sandbox_extension_issue
	Issued time.Time
	handle int64 // internal handle from consume, -1 if not consumed
}

// Manager tracks sandbox extension tokens.
type Manager struct {
	mu     sync.Mutex
	tokens map[string]*Token
}

// NewManager creates a new token manager.
func NewManager() *Manager {
	return &Manager{
		tokens: make(map[string]*Token),
	}
}

// Issue creates a sandbox extension token for the given path and class.
// Must be called from an unsandboxed process.
func (m *Manager) Issue(path string, class ExtClass) (*Token, error) {
	cClass := C.CString(string(class))
	defer C.free(unsafe.Pointer(cClass))

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cToken := C.sandbox_extension_issue_file(cClass, cPath, 0)
	if cToken == nil {
		return nil, fmt.Errorf("sandbox_extension_issue_file failed for %q", path)
	}

	tokenStr := C.GoString(cToken)
	C.free(unsafe.Pointer(cToken))

	tok := &Token{
		Path:   path,
		Class:  class,
		Value:  tokenStr,
		Issued: time.Now(),
		handle: -1,
	}

	m.mu.Lock()
	m.tokens[path] = tok
	m.mu.Unlock()

	return tok, nil
}

// ActiveTokens returns all currently issued tokens.
func (m *Manager) ActiveTokens() []Token {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokens := make([]Token, 0, len(m.tokens))
	for _, t := range m.tokens {
		tokens = append(tokens, *t)
	}
	return tokens
}

// Revoke releases a token for the given path.
func (m *Manager) Revoke(path string) error {
	m.mu.Lock()
	tok, ok := m.tokens[path]
	if !ok {
		m.mu.Unlock()
		return nil // already revoked, no error
	}
	delete(m.tokens, path)
	m.mu.Unlock()

	if tok.handle >= 0 {
		C.sandbox_extension_release(C.int64_t(tok.handle))
	}
	return nil
}

// RevokeAll releases all tokens.
func (m *Manager) RevokeAll() {
	m.mu.Lock()
	tokens := m.tokens
	m.tokens = make(map[string]*Token)
	m.mu.Unlock()

	for _, tok := range tokens {
		if tok.handle >= 0 {
			C.sandbox_extension_release(C.int64_t(tok.handle))
		}
	}
}

// ConsumeToken consumes an opaque token string, granting the calling process access.
// Returns the handle (>= 0 on success) or error.
// This is called by macwrap before sandbox_init.
func ConsumeToken(tokenStr string) (int64, error) {
	cToken := C.CString(tokenStr)
	defer C.free(unsafe.Pointer(cToken))

	handle := int64(C.sandbox_extension_consume(cToken))
	if handle == -1 {
		return -1, fmt.Errorf("sandbox_extension_consume failed")
	}
	return handle, nil
}

// TokenValues returns just the opaque token strings (for serialization into WrapperConfig).
func (m *Manager) TokenValues() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	values := make([]string, 0, len(m.tokens))
	for _, t := range m.tokens {
		values = append(values, t.Value)
	}
	return values
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/darwin/sandboxext/... -v`
Expected: all tests PASS. (Tests run on macOS with CGo enabled.)

- [ ] **Step 5: Commit**

```bash
git add internal/platform/darwin/sandboxext/
git commit -m "feat(sandboxext): add sandbox extension token manager"
```

---

### Task 5: macwrap — WrapperConfig and Token Consumption

**Files:**
- Modify: `cmd/agentsh-macwrap/config.go`
- Modify: `cmd/agentsh-macwrap/main.go`
- Modify: `cmd/agentsh-macwrap/config_test.go`

- [ ] **Step 1: Write failing tests for new config fields and file-based config**

Add to `cmd/agentsh-macwrap/config_test.go`:

```go
func TestLoadConfig_CompiledProfile(t *testing.T) {
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{
		"workspace_path": "/tmp/test",
		"compiled_profile": "(version 1)\n(deny default)\n",
		"extension_tokens": ["token1", "token2"]
	}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.CompiledProfile != "(version 1)\n(deny default)\n" {
		t.Errorf("compiled_profile = %q", cfg.CompiledProfile)
	}
	if len(cfg.ExtensionTokens) != 2 {
		t.Errorf("extension_tokens len = %d, want 2", len(cfg.ExtensionTokens))
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := dir + "/config.json"
	os.WriteFile(cfgFile, []byte(`{
		"workspace_path": "/from/file",
		"compiled_profile": "(version 1)\n(deny default)"
	}`), 0600)

	os.Setenv("AGENTSH_SANDBOX_CONFIG_FILE", cfgFile)
	os.Unsetenv("AGENTSH_SANDBOX_CONFIG")
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG_FILE")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.WorkspacePath != "/from/file" {
		t.Errorf("workspace_path = %q, want /from/file", cfg.WorkspacePath)
	}
	// File should be deleted after read
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Error("config file should be deleted after read")
	}
}

func TestLoadConfig_BackwardsCompatible(t *testing.T) {
	// Old-style config without compiled_profile should still work
	os.Setenv("AGENTSH_SANDBOX_CONFIG", `{
		"workspace_path": "/tmp/old",
		"allow_network": true,
		"mach_services": {"default_action": "allow"}
	}`)
	defer os.Unsetenv("AGENTSH_SANDBOX_CONFIG")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.CompiledProfile != "" {
		t.Error("compiled_profile should be empty for old config")
	}
	if cfg.WorkspacePath != "/tmp/old" {
		t.Errorf("workspace_path = %q", cfg.WorkspacePath)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/agentsh-macwrap/... -v -run 'TestLoadConfig_(CompiledProfile|FromFile|BackwardsCompatible)'`
Expected: FAIL — `CompiledProfile` field doesn't exist, `AGENTSH_SANDBOX_CONFIG_FILE` not handled.

- [ ] **Step 3: Update config.go with new fields and file loading**

Update `cmd/agentsh-macwrap/config.go`:

```go
//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// WrapperConfig is passed via AGENTSH_SANDBOX_CONFIG env var
// or AGENTSH_SANDBOX_CONFIG_FILE (for large payloads >64KB).
type WrapperConfig struct {
	WorkspacePath string            `json:"workspace_path"`
	AllowedPaths  []string          `json:"allowed_paths"`
	AllowNetwork  bool              `json:"allow_network"`
	MachServices  MachServicesConfig `json:"mach_services"`

	// New fields for dynamic seatbelt
	CompiledProfile string   `json:"compiled_profile,omitempty"`
	ExtensionTokens []string `json:"extension_tokens,omitempty"`
}

// MachServicesConfig controls mach-lookup restrictions.
type MachServicesConfig struct {
	DefaultAction string   `json:"default_action"`
	Allow         []string `json:"allow"`
	Block         []string `json:"block"`
	AllowPrefixes []string `json:"allow_prefixes"`
	BlockPrefixes []string `json:"block_prefixes"`
}

// loadConfig reads wrapper config from environment or file.
func loadConfig() (*WrapperConfig, error) {
	// Check for file-based config first (used for large payloads)
	if filePath := os.Getenv("AGENTSH_SANDBOX_CONFIG_FILE"); filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read config file %s: %w", filePath, err)
		}
		// Delete file after reading (best-effort)
		os.Remove(filePath)

		var cfg WrapperConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
		return &cfg, nil
	}

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

- [ ] **Step 4: Run config tests to verify they pass**

Run: `go test ./cmd/agentsh-macwrap/... -v -run TestLoadConfig`
Expected: all PASS.

- [ ] **Step 5: Update main.go to use compiled profile and consume tokens**

Update `cmd/agentsh-macwrap/main.go`. Add `consumeTokens` function and update `main()` to check `CompiledProfile`:

Add token consumption CGo declaration to the existing `import "C"` block — add after the `free_error` function:

```c
// sandbox_extension_consume consumes an extension token.
extern int64_t sandbox_extension_consume(const char *token);
```

Then add Go function and update `main()`:

```go
// consumeTokens consumes sandbox extension tokens before sandbox_init.
// Failures are warnings — the SBPL rule still provides access.
func consumeTokens(tokens []string) {
	for _, token := range tokens {
		cToken := C.CString(token)
		handle := C.sandbox_extension_consume(cToken)
		C.free(unsafe.Pointer(cToken))
		if handle == -1 {
			log.Printf("warning: failed to consume extension token (continuing)")
		}
	}
}

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

	// Consume extension tokens before sandbox_init
	if len(cfg.ExtensionTokens) > 0 {
		consumeTokens(cfg.ExtensionTokens)
	}

	// Use compiled profile if provided, otherwise fall back to legacy generation
	profile := cfg.CompiledProfile
	if profile == "" {
		profile = generateProfile(cfg)
	}

	if err := applySandbox(profile); err != nil {
		log.Fatalf("apply sandbox: %v", err)
	}

	if err := syscall.Exec(cmd, args, os.Environ()); err != nil {
		log.Fatalf("exec %s failed: %v", cmd, err)
	}
}
```

- [ ] **Step 6: Run all macwrap tests**

Run: `go test ./cmd/agentsh-macwrap/... -v`
Expected: all tests PASS (including existing profile tests — legacy path still works).

- [ ] **Step 7: Commit**

```bash
git add cmd/agentsh-macwrap/
git commit -m "feat(macwrap): add compiled profile support and token consumption"
```

---

### Task 6: Policy-to-Sandbox Compilation

**Files:**
- Modify: `internal/platform/darwin/sandbox.go`
- Create: `internal/platform/darwin/sandbox_compile_test.go`

- [ ] **Step 1: Write failing tests for CompileDarwinSandbox**

Create `internal/platform/darwin/sandbox_compile_test.go`:

```go
//go:build darwin

package darwin

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestCompileDarwinSandbox_EmptyPolicy(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	if !strings.Contains(cfg.Profile, "(deny default)") {
		t.Error("empty policy should produce deny-default profile")
	}
	if !strings.Contains(cfg.Profile, "(allow process-fork)") {
		t.Error("should contain system essentials")
	}
}

func TestCompileDarwinSandbox_FileRules(t *testing.T) {
	pol := &policy.Policy{
		FileRules: []policy.FileRule{
			{Paths: []string{"/data"}, Operations: []string{"read"}, Decision: "allow"},
			{Paths: []string{"/logs"}, Operations: []string{"write"}, Decision: "allow"},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	if !strings.Contains(cfg.Profile, `(subpath "/data")`) {
		t.Error("missing /data subpath rule")
	}
	if !strings.Contains(cfg.Profile, `file-write*`) {
		t.Error("write rule should include file-write*")
	}
	if len(cfg.TokenValues) < 2 {
		t.Errorf("expected at least 2 tokens, got %d", len(cfg.TokenValues))
	}
}

func TestCompileDarwinSandbox_CommandRules(t *testing.T) {
	pol := &policy.Policy{
		CommandRules: []policy.CommandRule{
			{Commands: []string{"/usr/bin/git"}, Decision: "allow"},
			{Commands: []string{"osascript"}, Decision: "deny"},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	if !strings.Contains(cfg.Profile, `(allow process-exec (literal "/usr/bin/git"))`) {
		t.Error("missing git exec allow")
	}
	if !strings.Contains(cfg.Profile, `(deny process-exec`) {
		t.Error("missing osascript exec deny")
	}
}

func TestCompileDarwinSandbox_NetworkAllowAll(t *testing.T) {
	pol := &policy.Policy{
		NetworkRules: []policy.NetworkRule{
			{Decision: "allow"},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	if !strings.Contains(cfg.Profile, "(allow network*)") {
		t.Error("should have network allow-all")
	}
}

func TestCompileDarwinSandbox_WorkspaceFullAccess(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "/Users/dev/project")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	if !strings.Contains(cfg.Profile, `(subpath "/Users/dev/project")`) {
		t.Error("workspace path should be in profile")
	}
	if !strings.Contains(cfg.Profile, "file-ioctl") {
		t.Error("workspace should have file-ioctl")
	}
}

func TestCompileDarwinSandbox_DefaultExecBlocklist(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	for _, blocked := range []string{"osascript", "security", "systemsetup", "tccutil", "csrutil"} {
		if !strings.Contains(cfg.Profile, blocked) {
			t.Errorf("default exec blocklist should contain %s", blocked)
		}
	}
}

func TestCompileDarwinSandbox_DefaultExecAllowPaths(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	for _, path := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/opt/homebrew/bin"} {
		if !strings.Contains(cfg.Profile, `(allow process-exec (subpath "`+path+`"))`) {
			t.Errorf("default exec allow should contain %s", path)
		}
	}
}

func TestCompileDarwinSandbox_MachEssentials(t *testing.T) {
	pol := &policy.Policy{}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	if !strings.Contains(cfg.Profile, "com.apple.system.logger") {
		t.Error("mach essentials should include system.logger")
	}
	if !strings.Contains(cfg.Profile, "com.apple.security.authtrampoline") {
		t.Error("mach blocklist should include authtrampoline")
	}
}

func TestCompileDarwinSandbox_DenyFileRuleOmitted(t *testing.T) {
	pol := &policy.Policy{
		FileRules: []policy.FileRule{
			{Paths: []string{"/secret"}, Decision: "deny"},
		},
	}
	cfg, err := CompileDarwinSandbox(pol, "/workspace")
	if err != nil {
		t.Fatalf("CompileDarwinSandbox: %v", err)
	}
	// Deny rules are handled by omission (deny-default)
	if strings.Contains(cfg.Profile, "/secret") {
		t.Error("deny file rules should be omitted from profile (deny-default handles them)")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/darwin/... -v -run TestCompileDarwinSandbox`
Expected: FAIL — `CompileDarwinSandbox` not defined.

- [ ] **Step 3: Implement CompileDarwinSandbox**

Add to `internal/platform/darwin/sandbox.go`, after the existing code:

```go
import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/platform/darwin/sbpl"
	"github.com/agentsh/agentsh/internal/platform/darwin/sandboxext"
	"github.com/agentsh/agentsh/internal/policy"
)

// SandboxConfig holds the compiled SBPL profile and extension tokens.
type SandboxConfig struct {
	Profile     string   // compiled SBPL string
	TokenValues []string // opaque token strings for macwrap
}

// Default exec blocklist — macOS tools that enable privilege escalation.
var defaultExecBlocklist = []string{
	"/usr/bin/osascript",
	"/usr/bin/security",
	"/usr/sbin/systemsetup",
	"/usr/bin/tccutil",
	"/usr/sbin/csrutil",
}

// Default exec path allowlist — standard tool directories.
var defaultExecAllowPaths = []string{
	"/usr/bin", "/bin", "/usr/sbin", "/sbin",
	"/usr/local/bin", "/opt/homebrew/bin",
}

// Default essential Mach services.
var defaultMachAllow = []string{
	"com.apple.system.logger",
	"com.apple.SecurityServer",
	"com.apple.distributed_notifications@Gv0",
	"com.apple.system.notification_center",
	"com.apple.CoreServices.coreservicesd",
	"com.apple.DiskArbitration.diskarbitrationd",
	"com.apple.xpc.launchd.domain.system",
}

// Default dangerous Mach services.
var defaultMachBlock = []string{
	"com.apple.security.authtrampoline",
	"com.apple.coreservices.launchservicesd",
	"com.apple.securityd",
}

// Default dangerous Mach prefixes.
var defaultMachBlockPrefixes = []string{
	"com.apple.pasteboard.",
}

// CompileDarwinSandbox builds an SBPL profile and extension tokens from a policy.
func CompileDarwinSandbox(pol *policy.Policy, workspacePath string) (*SandboxConfig, error) {
	p := sbpl.New()
	mgr := sandboxext.NewManager()
	defer mgr.RevokeAll() // Manager is only used for issuing; tokens are serialized out

	// System essentials
	p.AllowSystemEssentials()

	// Workspace (full access)
	if workspacePath != "" {
		absWs, err := filepath.Abs(workspacePath)
		if err == nil {
			workspacePath = absWs
		}
		p.AllowFileReadWriteIOctl(sbpl.Subpath, workspacePath)
		mgr.Issue(workspacePath, sandboxext.ReadWrite)
	}

	// File rules from policy
	for _, rule := range pol.FileRules {
		if rule.Decision != "allow" {
			continue // deny = omission (deny-default handles it)
		}
		for _, path := range rule.Paths {
			isWrite := containsAny(rule.Operations, "write", "*", "delete")
			match := classifyPath(path)

			if isWrite {
				p.AllowFileReadWrite(match, path)
				mgr.Issue(path, sandboxext.ReadWrite)
			} else {
				p.AllowFileRead(match, path)
				mgr.Issue(path, sandboxext.ReadOnly)
			}
		}
	}

	// Command rules — default exec blocklist
	for _, blocked := range defaultExecBlocklist {
		p.DenyProcessExec(sbpl.Literal, blocked)
	}

	// Default exec allow paths
	for _, allowPath := range defaultExecAllowPaths {
		p.AllowProcessExec(sbpl.Subpath, allowPath)
	}
	if workspacePath != "" {
		p.AllowProcessExec(sbpl.Subpath, workspacePath)
	}

	// Policy command rules
	for _, rule := range pol.CommandRules {
		for _, cmd := range rule.Commands {
			switch rule.Decision {
			case "allow":
				resolved := resolveCommand(cmd)
				p.AllowProcessExec(sbpl.Literal, resolved)
			case "deny":
				resolved := resolveCommand(cmd)
				p.DenyProcessExec(sbpl.Literal, resolved)
			// "approve", "redirect" — not mapped to SBPL (handled by shim/ESF)
			}
		}
	}

	// Network rules
	hasNetwork := false
	for _, rule := range pol.NetworkRules {
		if rule.Decision != "allow" {
			continue
		}
		if len(rule.Domains) > 0 || (len(rule.Ports) == 0 && len(rule.CIDRs) == 0) {
			// Domain rules or unrestricted allow → allow all network
			p.AllowNetworkAll()
			hasNetwork = true
			break
		}
		for _, port := range rule.Ports {
			p.AllowNetworkOutbound("tcp", fmt.Sprintf("*:%d", port))
			hasNetwork = true
		}
	}
	_ = hasNetwork // used if we need to log

	// Mach services — blocklist first
	for _, svc := range defaultMachBlock {
		p.DenyMachLookup(svc)
	}
	for _, prefix := range defaultMachBlockPrefixes {
		// DenyMachLookup doesn't support prefix — use the builder's deny support
		// For now, individual deny entries. Prefix deny requires adding DenyMachLookupPrefix.
		p.DenyMachLookup(prefix + "*") // This won't work in SBPL — see step below
	}
	// Essential allows
	for _, svc := range defaultMachAllow {
		p.AllowMachLookup(svc)
	}

	profile, err := p.Build()
	if err != nil {
		return nil, fmt.Errorf("build SBPL profile: %w", err)
	}

	return &SandboxConfig{
		Profile:     profile,
		TokenValues: mgr.TokenValues(),
	}, nil
}

// classifyPath determines whether a path should use Subpath or Literal matching.
func classifyPath(path string) sbpl.PathMatch {
	if strings.HasSuffix(path, "/*") || strings.HasSuffix(path, "/") {
		return sbpl.Subpath
	}
	// Check if path looks like a directory (no file extension in the last component)
	base := filepath.Base(path)
	if !strings.Contains(base, ".") {
		return sbpl.Subpath
	}
	return sbpl.Literal
}

// resolveCommand resolves a command name to an absolute path.
func resolveCommand(cmd string) string {
	if filepath.IsAbs(cmd) {
		return cmd
	}
	// Try to resolve via PATH
	if resolved, err := exec.LookPath(cmd); err == nil {
		return resolved
	}
	// Fallback: assume /usr/bin
	return "/usr/bin/" + cmd
}

// containsAny returns true if the slice contains any of the values.
func containsAny(slice []string, values ...string) bool {
	for _, s := range slice {
		for _, v := range values {
			if s == v {
				return true
			}
		}
	}
	return false
}
```

Note: We need to add `DenyMachLookupPrefix` to the builder. Add this quick method to `sbpl/builder.go`:

```go
// DenyMachLookupPrefix denies lookup of Mach services by prefix.
func (p *Profile) DenyMachLookupPrefix(prefix string) {
	p.rules = append(p.rules, rule{
		kind: kindMachDeny,
		sbpl: fmt.Sprintf("(deny mach-lookup (global-name-prefix %q))", prefix),
	})
}
```

Then fix the compilation code to use `DenyMachLookupPrefix` instead of the wildcard hack:

```go
	for _, prefix := range defaultMachBlockPrefixes {
		p.DenyMachLookupPrefix(prefix)
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/darwin/... -v -run TestCompileDarwinSandbox`
Expected: all tests PASS.

- [ ] **Step 5: Verify full build**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add internal/platform/darwin/sbpl/ internal/platform/darwin/sandbox*.go
git commit -m "feat(darwin): add CompileDarwinSandbox policy-to-SBPL compiler"
```

---

### Task 7: Server Integration — wrapWithMacSandbox

**Files:**
- Modify: `internal/api/core.go`

- [ ] **Step 1: Read current wrapWithMacSandbox to understand the call site**

Check `internal/api/core.go` lines 1401-1458 for the current implementation. The method modifies a `types.ExecRequest` in place: sets `req.Env["AGENTSH_SANDBOX_CONFIG"]`, replaces `req.Command` with the wrapper binary, and prepends `--` to args.

- [ ] **Step 2: Update macSandboxWrapperConfig with new fields**

In `internal/api/core.go`, update the `macSandboxWrapperConfig` struct (line 76):

```go
type macSandboxWrapperConfig struct {
	WorkspacePath string                       `json:"workspace_path"`
	AllowedPaths  []string                     `json:"allowed_paths"`
	AllowNetwork  bool                         `json:"allow_network"`
	MachServices  macSandboxMachServicesConfig `json:"mach_services"`

	// Dynamic seatbelt fields
	CompiledProfile string   `json:"compiled_profile,omitempty"`
	ExtensionTokens []string `json:"extension_tokens,omitempty"`
}
```

- [ ] **Step 3: Update wrapWithMacSandbox to compile profile from policy**

Replace the body of `wrapWithMacSandbox` (lines 1401-1458) to call `CompileDarwinSandbox`. The method already has access to `sess` (session) which has the workspace path, and `a.policy` which has the loaded policy:

```go
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

	if _, err := exec.LookPath(wrapperBin); err != nil {
		return
	}

	// Compile policy-driven SBPL profile
	sandboxCfg, err := darwin.CompileDarwinSandbox(a.policy, sess.Workspace)
	if err != nil {
		slog.Warn("failed to compile darwin sandbox profile, falling back to legacy",
			"error", err, "session", sess.ID)
		// Fall back to legacy config (no compiled profile)
		sandboxCfg = nil
	}

	// Build wrapper config
	cfg := macSandboxWrapperConfig{
		WorkspacePath: sess.Workspace,
		AllowedPaths:  []string{os.Getenv("HOME")},
		AllowNetwork:  true,
		MachServices: macSandboxMachServicesConfig{
			DefaultAction: a.cfg.Sandbox.XPC.MachServices.DefaultAction,
			Allow:         a.cfg.Sandbox.XPC.MachServices.Allow,
			Block:         a.cfg.Sandbox.XPC.MachServices.Block,
			AllowPrefixes: a.cfg.Sandbox.XPC.MachServices.AllowPrefixes,
			BlockPrefixes: a.cfg.Sandbox.XPC.MachServices.BlockPrefixes,
		},
	}

	if sandboxCfg != nil {
		cfg.CompiledProfile = sandboxCfg.Profile
		cfg.ExtensionTokens = sandboxCfg.TokenValues
	}

	// Apply mach defaults if not configured
	if cfg.MachServices.DefaultAction == "" {
		cfg.MachServices.DefaultAction = "deny"
	}
	if len(cfg.MachServices.Allow) == 0 && cfg.MachServices.DefaultAction == "deny" {
		cfg.MachServices.Allow = DefaultXPCAllowList
	}
	if len(cfg.MachServices.BlockPrefixes) == 0 && cfg.MachServices.DefaultAction == "allow" {
		cfg.MachServices.BlockPrefixes = DefaultXPCBlockPrefixes
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return
	}

	if req.Env == nil {
		req.Env = map[string]string{}
	}

	// Use file-based config if payload is too large for env var
	cfgStr := string(cfgJSON)
	if len(cfgStr) > 64*1024 {
		tmpFile := fmt.Sprintf("/tmp/agentsh-sandbox-%s.json", sess.ID)
		if err := os.WriteFile(tmpFile, cfgJSON, 0600); err != nil {
			slog.Warn("failed to write sandbox config file", "error", err)
			return
		}
		req.Env["AGENTSH_SANDBOX_CONFIG_FILE"] = tmpFile
	} else {
		req.Env["AGENTSH_SANDBOX_CONFIG"] = cfgStr
	}

	req.Command = wrapperBin
	req.Args = append([]string{"--", origCommand}, origArgs...)
}
```

Note: You'll need to add the import for the darwin package. Since `core.go` is not build-tagged, and `CompileDarwinSandbox` is darwin-only, you'll need to either:
- Add a build-tagged helper file `internal/api/sandbox_darwin.go` that wraps the call, OR
- Use a compile-time interface

The cleanest approach: create `internal/api/sandbox_darwin.go` and `internal/api/sandbox_other.go`:

`sandbox_darwin.go`:
```go
//go:build darwin

package api

import (
	"github.com/agentsh/agentsh/internal/platform/darwin"
	"github.com/agentsh/agentsh/internal/policy"
)

func compileDarwinSandbox(pol *policy.Policy, workspace string) (*darwin.SandboxConfig, error) {
	return darwin.CompileDarwinSandbox(pol, workspace)
}
```

`sandbox_other.go`:
```go
//go:build !darwin

package api

import "github.com/agentsh/agentsh/internal/policy"

type darwinSandboxConfig struct {
	Profile     string
	TokenValues []string
}

func compileDarwinSandbox(pol *policy.Policy, workspace string) (*darwinSandboxConfig, error) {
	return nil, nil
}
```

Then in `wrapWithMacSandbox`, call `compileDarwinSandbox(a.policy, sess.Workspace)`.

- [ ] **Step 4: Verify build compiles on all platforms**

Run: `go build ./...` and `GOOS=linux go build ./...` and `GOOS=windows go build ./...`
Expected: all pass.

- [ ] **Step 5: Run existing server tests**

Run: `go test ./internal/api/... -v -count=1`
Expected: all existing tests PASS (backwards compatible).

- [ ] **Step 6: Commit**

```bash
git add internal/api/core.go internal/api/sandbox_darwin.go internal/api/sandbox_other.go
git commit -m "feat(api): wire CompileDarwinSandbox into wrapWithMacSandbox"
```

---

### Task 8: Capability Detection Updates

**Files:**
- Modify: `internal/capabilities/detect_darwin.go`

- [ ] **Step 1: Read current detection logic for context**

Review `internal/capabilities/detect_darwin.go` (already read). Key changes:
- `selectDarwinMode` needs new tiers for dynamic seatbelt
- `buildDarwinDomains` needs command_control and isolation to be always-available
- Check if `agentsh-macwrap` is in PATH for dynamic seatbelt detection

- [ ] **Step 2: Update selectDarwinMode with new tiers**

```go
func selectDarwinMode(caps map[string]any) (string, int) {
	if esf, _ := caps["esf"].(bool); esf {
		return "esf", 90
	}
	if lima, _ := caps["lima_available"].(bool); lima {
		return "lima", 85
	}

	hasMacwrap := checkMacwrap()
	fuset, _ := caps["fuse_t"].(bool)

	if hasMacwrap && fuset {
		return "dynamic-seatbelt-fuse", 75
	}
	if fuset {
		return "fuse-t", 70
	}
	if hasMacwrap {
		return "dynamic-seatbelt", 65
	}
	return "sandbox-exec", 60
}

func checkMacwrap() bool {
	_, err := exec.LookPath("agentsh-macwrap")
	return err == nil
}
```

- [ ] **Step 3: Update buildDarwinDomains to reflect dynamic seatbelt**

```go
func buildDarwinDomains(caps map[string]any) []ProtectionDomain {
	fuseT, _ := caps["fuse_t"].(bool)
	esf, _ := caps["esf"].(bool)
	networkExt, _ := caps["network_extension"].(bool)
	hasMacwrap := checkMacwrap()

	fuseDetail := "not installed"
	if fuseT {
		fuseDetail = "FUSE-T"
	}

	macwrapDetail := "not found"
	if hasMacwrap {
		macwrapDetail = "dynamic seatbelt"
	}

	return []ProtectionDomain{
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "fuse-t", Available: fuseT, Detail: fuseDetail, Description: "filesystem interception", CheckMethod: "binary"},
				{Name: "esf", Available: esf, Detail: "", Description: "Endpoint Security Framework", CheckMethod: "entitlement"},
			},
		},
		{
			Name: "Command Control", Weight: WeightCommandControl,
			Backends: []DetectedBackend{
				{Name: "esf", Available: esf, Detail: "", Description: "process execution control", CheckMethod: "entitlement"},
				{Name: "dynamic-seatbelt", Available: hasMacwrap, Detail: macwrapDetail, Description: "policy-driven exec restriction", CheckMethod: "binary"},
				{Name: "sandbox-exec", Available: true, Detail: "", Description: "macOS sandbox", CheckMethod: "builtin"},
			},
			Active: func() string {
				if esf { return "esf" }
				if hasMacwrap { return "dynamic-seatbelt" }
				return "sandbox-exec"
			}(),
		},
		{
			Name: "Network", Weight: WeightNetwork,
			Backends: []DetectedBackend{
				{Name: "network-extension", Available: networkExt, Detail: "", Description: "network filtering", CheckMethod: "entitlement"},
			},
		},
		{
			Name: "Resource Limits", Weight: WeightResourceLimits,
			Backends: []DetectedBackend{
				{Name: "launchd-limits", Available: true, Detail: "", Description: "launchd resource limits", CheckMethod: "builtin"},
			},
			Active: "launchd-limits",
		},
		{
			Name: "Isolation", Weight: WeightIsolation,
			Backends: []DetectedBackend{
				{Name: "dynamic-seatbelt", Available: hasMacwrap, Detail: macwrapDetail, Description: "deny-default sandbox", CheckMethod: "binary"},
				{Name: "sandbox-exec", Available: true, Detail: "", Description: "process isolation", CheckMethod: "builtin"},
			},
			Active: func() string {
				if hasMacwrap { return "dynamic-seatbelt" }
				return "sandbox-exec"
			}(),
		},
	}
}
```

- [ ] **Step 4: Build and run existing capability tests**

Run: `go test ./internal/capabilities/... -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/capabilities/detect_darwin.go
git commit -m "feat(capabilities): add dynamic seatbelt tiers for macOS"
```

---

### Task 9: Profile Artifact — Debug File

**Files:**
- Modify: `internal/api/core.go` (or the new `sandbox_darwin.go`)

- [ ] **Step 1: Add profile artifact writing to wrapWithMacSandbox**

After building the compiled profile, write it to the session directory for debugging. Add to `wrapWithMacSandbox` after the profile is compiled:

```go
	// Write profile artifact for debugging/inspection
	if sandboxCfg != nil && sandboxCfg.Profile != "" && sess.ID != "" {
		artifactDir := filepath.Join(os.Getenv("HOME"), ".agentsh", "sessions", sess.ID)
		os.MkdirAll(artifactDir, 0700)
		artifactPath := filepath.Join(artifactDir, "sandbox.sb")
		if err := os.WriteFile(artifactPath, []byte(sandboxCfg.Profile), 0600); err != nil {
			slog.Debug("failed to write sandbox profile artifact", "error", err)
		}
	}
```

- [ ] **Step 2: Build and verify**

Run: `go build ./...`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/api/
git commit -m "feat(api): write sandbox profile artifact to session directory"
```

---

### Task 10: Cross-Compilation Verification and Full Test

**Files:** All

- [ ] **Step 1: Verify cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: no errors (new darwin-only packages should not affect other platforms).

Run: `GOOS=linux go build ./...`
Expected: no errors.

- [ ] **Step 2: Run all tests**

Run: `go test ./...`
Expected: all tests PASS.

- [ ] **Step 3: Verify the SBPL builder tests run on any platform**

The `sbpl/` package has no build tags — its tests should run everywhere.

Run: `go test ./internal/platform/darwin/sbpl/... -v`
Expected: PASS (pure Go, no CGo dependency).

- [ ] **Step 4: Final commit if any cleanup needed**

```bash
git add -A
git status  # verify no unexpected files
# Only commit if there are changes
```
