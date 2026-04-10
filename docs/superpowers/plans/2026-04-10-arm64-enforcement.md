# arm64 Enforcement + Detect Accuracy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix arm64 releases to ship with full seccomp/Landlock enforcement, and make `agentsh detect` report accurate scores when the wrapper binary is missing.

**Architecture:** Two independent changes — (1) cross-compile unixwrap and the server binary for arm64 with CGO enabled using the existing release runner, and (2) add a wrapper-availability check to the detect command that marks seccomp/Landlock backends as unavailable when the wrapper is not on PATH.

**Tech Stack:** GoReleaser, GitHub Actions, Go build tags, libseccomp cross-compilation

**Spec:** `docs/superpowers/specs/2026-04-10-arm64-enforcement-design.md`

---

### Task 1: Add wrapper availability check to detect

**Files:**
- Modify: `internal/capabilities/detect_linux.go:170-203`
- Modify: `internal/capabilities/detect_linux_test.go`

The detect change is implemented first (TDD — test, then code) so the regression becomes visible before fixing the build.

- [ ] **Step 1: Add mockable LookPath var to detect_linux.go**

Add a package-level var at the top of the file (after the imports) so tests can override the lookup. This follows the existing pattern used by `checkPtrace`, `checkSeccompUserNotify`, etc. in `check.go`:

```go
import (
	"fmt"
	"os/exec"
)

// wrapperLookPath is the function used to check if the wrapper binary exists.
// Package-level var for testability (matches checkPtrace pattern in check.go).
var wrapperLookPath = exec.LookPath
```

- [ ] **Step 2: Write failing test for wrapper-missing scenario**

Add to `internal/capabilities/detect_linux_test.go`:

```go
func TestApplyWrapperAvailability_Missing(t *testing.T) {
	// Build domains with all backends available
	caps := &SecurityCapabilities{
		Seccomp:      true,
		Landlock:     true,
		LandlockABI:  5,
		FUSE:         true,
		Ptrace:       true,
	}
	caps.FileEnforcement = detectFileEnforcementBackend(caps)
	domains := buildLinuxDomains(caps)

	// Wrapper not found
	found := applyWrapperAvailability(domains, caps)
	if found {
		t.Fatal("applyWrapperAvailability returned true, want false")
	}

	// Check affected backends are unavailable
	for _, d := range domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "seccomp-notify", "landlock", "seccomp-execve":
				if b.Available {
					t.Errorf("backend %q should be unavailable when wrapper missing", b.Name)
				}
			case "fuse", "ptrace":
				if !b.Available {
					t.Errorf("backend %q should remain available when wrapper missing", b.Name)
				}
			}
		}
	}

	// FileEnforcement should fall back to fuse
	if caps.FileEnforcement != "fuse" {
		t.Errorf("FileEnforcement = %q, want 'fuse'", caps.FileEnforcement)
	}
}

func TestApplyWrapperAvailability_Missing_NoFUSE(t *testing.T) {
	caps := &SecurityCapabilities{
		Seccomp:     true,
		Landlock:    true,
		LandlockABI: 5,
		FUSE:        false,
		Ptrace:      true,
	}
	caps.FileEnforcement = detectFileEnforcementBackend(caps)
	domains := buildLinuxDomains(caps)

	found := applyWrapperAvailability(domains, caps)
	if found {
		t.Fatal("applyWrapperAvailability returned true, want false")
	}

	// FileEnforcement should fall back to none
	if caps.FileEnforcement != "none" {
		t.Errorf("FileEnforcement = %q, want 'none'", caps.FileEnforcement)
	}
}

func TestApplyWrapperAvailability_Present(t *testing.T) {
	caps := &SecurityCapabilities{
		Seccomp:     true,
		Landlock:    true,
		LandlockABI: 5,
		FUSE:        true,
		Ptrace:      true,
	}
	caps.FileEnforcement = detectFileEnforcementBackend(caps)
	domains := buildLinuxDomains(caps)

	// Simulate wrapper found
	found := applyWrapperAvailability(domains, caps)
	// On CI/dev machines, wrapper may or may not be on PATH — just verify consistency
	if found {
		// All backends should remain as probed
		for _, d := range domains {
			for _, b := range d.Backends {
				switch b.Name {
				case "seccomp-notify", "seccomp-execve":
					if !b.Available {
						t.Errorf("backend %q should be available when wrapper present", b.Name)
					}
				}
			}
		}
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/capabilities/ -run TestApplyWrapperAvailability -v`
Expected: compilation error — `applyWrapperAvailability` not defined.

- [ ] **Step 4: Implement applyWrapperAvailability**

Add to `internal/capabilities/detect_linux.go`, before the `Detect()` function:

```go
// wrapperDependentBackends lists backends that require agentsh-unixwrap.
// These are marked unavailable when the wrapper binary is not on PATH.
var wrapperDependentBackends = map[string]bool{
	"seccomp-notify": true,
	"landlock":       true,
	"seccomp-execve": true,
}

// applyWrapperAvailability checks if agentsh-unixwrap is on PATH and marks
// wrapper-dependent backends as unavailable if it's missing. Also updates
// secCaps.FileEnforcement and domain Active fields for consistency.
// Returns true if the wrapper was found.
func applyWrapperAvailability(domains []ProtectionDomain, secCaps *SecurityCapabilities) bool {
	_, err := wrapperLookPath("agentsh-unixwrap")
	if err == nil {
		return true
	}

	// Wrapper missing — disable dependent backends
	for i := range domains {
		activeDisabled := false
		for j := range domains[i].Backends {
			if wrapperDependentBackends[domains[i].Backends[j].Name] {
				if domains[i].Backends[j].Name == domains[i].Active {
					activeDisabled = true
				}
				domains[i].Backends[j].Available = false
			}
		}
		// Fall back Active to next available backend
		if activeDisabled {
			domains[i].Active = ""
			for _, b := range domains[i].Backends {
				if b.Available {
					domains[i].Active = b.Name
					break
				}
			}
		}
	}

	// Update FileEnforcement to match
	switch secCaps.FileEnforcement {
	case "landlock", "seccomp-notify":
		if secCaps.FUSE {
			secCaps.FileEnforcement = "fuse"
		} else {
			secCaps.FileEnforcement = "none"
		}
	}

	return false
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/capabilities/ -run TestApplyWrapperAvailability -v`
Expected: PASS (all three test functions).

- [ ] **Step 6: Wire applyWrapperAvailability into Detect()**

Modify `internal/capabilities/detect_linux.go`, function `Detect()` (lines 171-203). Insert the wrapper check between `buildLinuxDomains` and `ComputeScore`, and append the wrapper-missing tip after `GenerateTipsFromDomains`:

```go
func Detect() (*DetectResult, error) {
	secCaps := DetectSecurityCapabilities()
	secCaps.FileEnforcement = detectFileEnforcementBackend(secCaps)

	domains := buildLinuxDomains(secCaps)

	// Check wrapper availability before scoring — marks seccomp/landlock
	// backends unavailable if agentsh-unixwrap is not on PATH.
	wrapperFound := applyWrapperAvailability(domains, secCaps)

	score := ComputeScore(domains)
	mode := secCaps.SelectMode()

	caps := backwardCompatCaps(secCaps, domains)

	var available, unavailable []string
	for _, d := range domains {
		for _, b := range d.Backends {
			if b.Available {
				available = append(available, b.Name)
			} else {
				unavailable = append(unavailable, b.Name)
			}
		}
	}

	tips := GenerateTipsFromDomains(domains)

	// Add wrapper-specific tip regardless of domain score (FUSE may keep
	// File Protection scored, but the missing wrapper is still actionable).
	if !wrapperFound {
		tips = append(tips, Tip{
			Feature: "seccomp-wrapper",
			Status:  "missing",
			Impact:  "seccomp and Landlock enforcement disabled — processes run without kernel-level interception",
			Action:  "install agentsh-unixwrap or rebuild the package with CGO_ENABLED=1",
		})
	}

	return &DetectResult{
		Platform:        "linux",
		SecurityMode:    mode,
		ProtectionScore: score,
		Domains:         domains,
		Capabilities:    caps,
		Summary:         DetectSummary{Available: available, Unavailable: unavailable},
		Tips:            tips,
	}, nil
}
```

- [ ] **Step 7: Add test for wrapper-missing tip in Detect output**

Add to `internal/capabilities/detect_linux_test.go`:

```go
func TestDetect_WrapperMissing_Tip(t *testing.T) {
	// Override LookPath to simulate missing wrapper
	orig := wrapperLookPath
	wrapperLookPath = func(file string) (string, error) {
		if file == "agentsh-unixwrap" {
			return "", exec.ErrNotFound
		}
		return exec.LookPath(file)
	}
	defer func() { wrapperLookPath = orig }()

	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// seccomp-notify, landlock, seccomp-execve should be unavailable
	for _, d := range result.Domains {
		for _, b := range d.Backends {
			switch b.Name {
			case "seccomp-notify", "landlock", "seccomp-execve":
				if b.Available {
					t.Errorf("backend %q should be unavailable when wrapper missing", b.Name)
				}
			}
		}
	}

	// Wrapper tip should be present
	found := false
	for _, tip := range result.Tips {
		if tip.Feature == "seccomp-wrapper" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected seccomp-wrapper tip when wrapper missing")
	}
}
```

Add `"os/exec"` to the imports at the top of the test file.

- [ ] **Step 8: Run all detect tests**

Run: `go test ./internal/capabilities/ -run TestDetect -v`
Expected: PASS for all tests (existing + new).

- [ ] **Step 9: Run full test suite**

Run: `go test ./...`
Expected: PASS — no regressions.

- [ ] **Step 10: Commit**

```bash
git add internal/capabilities/detect_linux.go internal/capabilities/detect_linux_test.go
git commit -m "fix(detect): mark seccomp/landlock backends unavailable when wrapper binary missing

detect now checks for agentsh-unixwrap on PATH and marks seccomp-notify,
landlock, and seccomp-execve backends as unavailable when it's not found.
This makes the protection score reflect actual enforcement state rather
than just kernel capabilities."
```

---

### Task 2: Add unixwrap arm64 build target to GoReleaser

**Files:**
- Modify: `.goreleaser.yml:24-36` (server arm64 build)
- Modify: `.goreleaser.yml:90-103` (add unixwrap arm64 after existing amd64 target)
- Modify: `.goreleaser.yml:148-159` (archives)
- Modify: `.goreleaser.yml:214-223` (nfpms)

- [ ] **Step 1: Flip server arm64 build to CGO_ENABLED=1**

In `.goreleaser.yml`, replace the `agentsh-linux-arm64` build (lines 24-36):

Old:
```yaml
  # Linux arm64: CGO disabled (cross-compilation complexity)
  # Users get graceful degradation - seccomp features unavailable
  - id: agentsh-linux-arm64
    main: ./cmd/agentsh
    binary: agentsh
    env:
      - CGO_ENABLED=0
    goos:
      - linux
    goarch:
      - arm64
    ldflags:
      - -s -w -X main.version={{.Version}} -X main.commit={{.ShortCommit}}
```

New:
```yaml
  # Linux arm64: CGO enabled for seccomp user-notify support (cross-compiled)
  - id: agentsh-linux-arm64
    main: ./cmd/agentsh
    binary: agentsh
    env:
      - CGO_ENABLED=1
      - CC=aarch64-linux-gnu-gcc
      - PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
    goos:
      - linux
    goarch:
      - arm64
    ldflags:
      - -s -w -X main.version={{.Version}} -X main.commit={{.ShortCommit}}
```

- [ ] **Step 2: Add unixwrap arm64 build target**

In `.goreleaser.yml`, after the `unixwrap-linux-amd64` build (after line 103), add:

```yaml
  # unixwrap: seccomp wrapper for Linux arm64 (cross-compiled)
  - id: unixwrap-linux-arm64
    main: ./cmd/agentsh-unixwrap
    binary: agentsh-unixwrap
    env:
      - CGO_ENABLED=1
      - CC=aarch64-linux-gnu-gcc
      - PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig
    goos:
      - linux
    goarch:
      - arm64
    ldflags:
      - -s -w
```

Also update the comment on the existing amd64 target (lines 90-91). Replace:
```yaml
  # unixwrap: seccomp wrapper for Linux (requires CGO + libseccomp)
  # Only building amd64 - arm64 cross-compilation requires libseccomp-dev:arm64
  # which is complex to set up in CI. arm64 users get graceful degradation.
```
With:
```yaml
  # unixwrap: seccomp wrapper for Linux amd64 (requires CGO + libseccomp)
```

- [ ] **Step 3: Add unixwrap-linux-arm64 to archives**

In `.goreleaser.yml`, in the `agentsh-linux` archive section, add `unixwrap-linux-arm64` to the `ids` list and remove `allow_different_binary_count: true`:

Old:
```yaml
  - id: agentsh-linux
    ids:
      - agentsh-linux-amd64
      - agentsh-linux-arm64
      - shim-linux
      - unixwrap-linux-amd64
      - stub-linux
    formats: [tar.gz]
    name_template: "{{ .ProjectName }}_{{ .Version }}_linux_{{ .Arch }}"
    # unixwrap only built for amd64, so binary count differs from arm64
    allow_different_binary_count: true
```

New:
```yaml
  - id: agentsh-linux
    ids:
      - agentsh-linux-amd64
      - agentsh-linux-arm64
      - shim-linux
      - unixwrap-linux-amd64
      - unixwrap-linux-arm64
      - stub-linux
    formats: [tar.gz]
    name_template: "{{ .ProjectName }}_{{ .Version }}_linux_{{ .Arch }}"
```

- [ ] **Step 4: Add unixwrap-linux-arm64 to nfpms**

In `.goreleaser.yml`, in the `nfpms` section, add `unixwrap-linux-arm64` to the `ids` list and remove the degradation comment:

Old:
```yaml
  - id: agentsh
    package_name: agentsh
    ids:
      - agentsh-linux-amd64
      - agentsh-linux-arm64
      - shim-linux
      - unixwrap-linux-amd64
      - stub-linux
      # unixwrap not available for arm64 - users get graceful degradation
```

New:
```yaml
  - id: agentsh
    package_name: agentsh
    ids:
      - agentsh-linux-amd64
      - agentsh-linux-arm64
      - shim-linux
      - unixwrap-linux-amd64
      - unixwrap-linux-arm64
      - stub-linux
```

- [ ] **Step 5: Verify GoReleaser config parses**

Run: `goreleaser check` (if goreleaser is installed locally), or validate YAML syntax:
Run: `go run github.com/goreleaser/goreleaser/v2@v2.13.1 check 2>&1 || echo "goreleaser not available — verify YAML manually"`

If goreleaser is not installed, verify the YAML is valid:
Run: `python3 -c "import yaml; yaml.safe_load(open('.goreleaser.yml'))" && echo "YAML valid"`

- [ ] **Step 6: Commit**

```bash
git add .goreleaser.yml
git commit -m "build: add arm64 unixwrap target + enable CGO for arm64 server

Cross-compile agentsh-unixwrap and the server binary for arm64 with
CGO_ENABLED=1 using aarch64-linux-gnu-gcc. Both architectures now ship
with full seccomp/Landlock/signal enforcement."
```

---

### Task 3: Add libseccomp-dev:arm64 to release CI

**Files:**
- Modify: `.github/workflows/release.yml:43-51`

- [ ] **Step 1: Add multi-arch apt and libseccomp-dev:arm64**

In `.github/workflows/release.yml`, replace the "Install build deps" step (lines 43-51):

Old:
```yaml
      - name: Install build deps (envshim, fuse, seccomp)
        run: |
          sudo apt-get update
          sudo apt-get install -y \
            libseccomp-dev \
            libfuse-dev \
            pkg-config \
            gcc-aarch64-linux-gnu \
            make
```

New:
```yaml
      - name: Install build deps (envshim, fuse, seccomp)
        run: |
          sudo dpkg --add-architecture arm64
          sudo apt-get update
          sudo apt-get install -y \
            libseccomp-dev \
            libseccomp-dev:arm64 \
            libfuse-dev \
            pkg-config \
            gcc-aarch64-linux-gnu \
            make
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add libseccomp-dev:arm64 for arm64 cross-compilation

Enables multi-arch apt and installs the arm64 libseccomp headers so
GoReleaser can cross-compile agentsh-unixwrap and the server binary
for arm64 with CGO enabled."
```

---

### Task 4: Verify cross-compilation locally

- [ ] **Step 1: Verify arm64 server builds with CGO**

Run:
```bash
CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/agentsh
```
Expected: build succeeds (exit 0). If `aarch64-linux-gnu-gcc` or `libseccomp-dev:arm64` is not installed locally, this will fail — that's fine, CI will handle it. Log the result either way.

- [ ] **Step 2: Verify arm64 unixwrap builds with CGO**

Run:
```bash
CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/agentsh-unixwrap
```
Expected: same as above — succeeds if cross-compile toolchain is present.

- [ ] **Step 3: Verify amd64 builds are unaffected**

Run:
```bash
go build ./...
go test ./...
```
Expected: PASS — no regressions on the native architecture.

- [ ] **Step 4: Verify Windows cross-compile is unaffected**

Run:
```bash
GOOS=windows go build ./...
```
Expected: PASS.

- [ ] **Step 5: Commit (no code changes — verification only)**

No commit needed. If any verification step surfaced issues, fix them and commit as part of the relevant task.
