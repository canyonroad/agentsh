# Issue #365 — Phase 1 Watchtower wiring fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three real defects from the Watchtower smoke test: register an OCSF projector for `cgroup_mode`, harden the exhaustiveness AST scanner to catch `Type: string(events.EventX)` form, and add an `audit.watchtower.agent_id` config field with hostname fallback.

**Architecture:** All three items are additive, non-breaking changes. The `cgroup_mode` projector slots into the existing `infraMappings` table in `project_app.go` with a new `AppActivityCgroupMode = 151` constant. The AST scanner gains a pre-pass that loads `EventX → "value"` from `internal/events/types.go`, plus a CallExpr branch in the existing walker. The `agent_id` field is added to `AuditWatchtowerConfig`, resolved at store-construction time via a new private `resolveAgentID(cfg)` helper exported through a thin `ResolveAgentIDForTest`.

**Tech Stack:** Go 1.22+, existing `internal/ocsf` projector pattern, existing `internal/server/wtp.go` config-resolution helpers pattern.

**Spec:** `docs/superpowers/specs/2026-05-20-issue-365-watchtower-phase1-fixes-design.md`

---

### Task 1: Add `AppActivityCgroupMode` constant

**Files:**
- Modify: `internal/ocsf/activity.go` (add one const in the agentsh-internal Application Activity block)

- [ ] **Step 1: Locate the existing cgroup activity constants**

Run: `grep -n "AppActivityCgroup" internal/ocsf/activity.go`

Expected output:
```
73:	AppActivityCgroupApplied            uint32 = 102
91:	AppActivityCgroupApplyFailed        uint32 = 140
92:	AppActivityCgroupCleanupFailed      uint32 = 141
```

Slot `151` is free (between `AppActivityNetProxyFailed = 150` at line 100 and `AppActivityMCPToolChanged = 153` at line 101). Confirm by:

```bash
grep -n "uint32 = 15" internal/ocsf/activity.go
```

Expected: lines for `150`, `153`, `155` — no `151`.

- [ ] **Step 2: Add the new constant**

Open `internal/ocsf/activity.go`. After the line `AppActivityNetProxyFailed           uint32 = 150` (around line 100), insert:

```go
	AppActivityCgroupMode               uint32 = 151
```

The full block context (after edit) should read:

```go
	AppActivityLLMProxyFailed           uint32 = 149
	AppActivityNetProxyFailed           uint32 = 150
	AppActivityCgroupMode               uint32 = 151
	AppActivityMCPToolChanged           uint32 = 153
```

- [ ] **Step 3: Build the package**

Run: `go build ./internal/ocsf/`
Expected: clean build, no output.

- [ ] **Step 4: Commit**

```bash
git add internal/ocsf/activity.go
git commit -m "$(cat <<'EOF'
ocsf: add AppActivityCgroupMode activity id (151) for cgroup_mode

Slot in the agentsh-internal Application Activity range. Registration
of the cgroup_mode event type follows in a subsequent commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Register `cgroup_mode` projector — failing test first

**Files:**
- Modify: `internal/ocsf/mapper_test.go` (extend `goldenSampleEvents` with a `cgroup_mode` event)
- Create: `internal/ocsf/testdata/golden/cgroup_mode.json` (in Step 6 after registration lands)

- [ ] **Step 1: Add a fixture event to `goldenSampleEvents`**

Open `internal/ocsf/mapper_test.go`. Find the `goldenSampleEvents` function (returns `[]types.Event`). Locate the line:

```go
		{ID: "ev-cgroup-applied-1", Type: "cgroup_applied", Timestamp: t0},
```

(Around line 391.) Immediately after that line, insert:

```go
		{ID: "ev-cgroup-mode-1", Type: "cgroup_mode", Timestamp: t0,
			Fields: map[string]any{
				"mode":         "user_namespace",
				"reason":       "no_root_cgroup_writable",
				"own_cgroup":   "/user.slice/user-1000.slice/agentsh",
				"slice_dir":    "/user.slice/user-1000.slice",
				"io_available": true,
				"leaf_moved":   false,
			}},
```

- [ ] **Step 2: Add an exhaustiveness assertion test**

In the same file, find the existing test
`TestMap_UnmappedTypeReturnsErrUnmappedType` (around line 22) and below it add this new test. Use the same imports already present in the file (`testing`, the `ocsf` package's `New()`).

```go
// TestMap_CgroupModeRegistered verifies the cgroup_mode startup event
// has an OCSF projector. Regression test for issue #365.
func TestMap_CgroupModeRegistered(t *testing.T) {
	m := New()
	ev := types.Event{
		ID:        "ev-cgroup-mode-probe",
		Type:      "cgroup_mode",
		Timestamp: time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		Fields: map[string]any{
			"mode":   "user_namespace",
			"reason": "no_root_cgroup_writable",
		},
	}
	mapped, err := m.Map(ev)
	if err != nil {
		t.Fatalf("Map(cgroup_mode) error: %v", err)
	}
	if mapped.OCSFClassUID != ClassApplicationActivity {
		t.Errorf("ClassUID = %d, want %d", mapped.OCSFClassUID, ClassApplicationActivity)
	}
	if mapped.OCSFActivityID != AppActivityCgroupMode {
		t.Errorf("ActivityID = %d, want %d", mapped.OCSFActivityID, AppActivityCgroupMode)
	}
}
```

- [ ] **Step 3: Run the new test to verify it fails**

Run: `go test -run TestMap_CgroupModeRegistered -v ./internal/ocsf/`

Expected: FAIL with `Map(cgroup_mode) error: ocsf: event Type not registered: "cgroup_mode"`.

- [ ] **Step 4: Run the exhaustiveness test to confirm CI is currently still silent**

Run: `go test -run TestExhaustiveness_AllEventTypesRegistered -v ./internal/ocsf/`

Expected: PASS — confirms the scanner gap (the AST walker can't see `string(events.EventCgroupMode)` at `internal/server/server.go:492`). This is the gap Task 4 fixes.

- [ ] **Step 5: Register the projector and extend the allowlist**

Open `internal/ocsf/project_app.go`. In the `init()` function, find the `infraMappings` map. Insert one new entry, placed alphabetically near the other cgroup_* entries:

```go
		"cgroup_applied":              AppActivityCgroupApplied,
		"cgroup_apply_failed":         AppActivityCgroupApplyFailed,
		"cgroup_cleanup_failed":       AppActivityCgroupCleanupFailed,
		"cgroup_mode":                 AppActivityCgroupMode,
```

Then find the `infraAllow` slice (the three-entry `[]FieldRule` block declaring `reason`, `policy_name`, `rotation_reason`). Replace it with the extended set:

```go
	infraAllow := []FieldRule{
		{Key: "reason", Transform: AsString, DestPath: "enrichments.reason"},
		{Key: "policy_name", Transform: AsString, DestPath: "enrichments.policy_name"},
		{Key: "rotation_reason", Transform: AsString, DestPath: "enrichments.rotation_reason"},
		{Key: "mode", Transform: AsString, DestPath: "enrichments.mode"},
		{Key: "own_cgroup", Transform: AsString, DestPath: "enrichments.own_cgroup"},
		{Key: "slice_dir", Transform: AsString, DestPath: "enrichments.slice_dir"},
		{Key: "io_available", Transform: AsString, DestPath: "enrichments.io_available"},
		{Key: "leaf_moved", Transform: AsString, DestPath: "enrichments.leaf_moved"},
	}
```

All five new transforms are `AsString` — the consumer is `appProjector`'s `map[string]string` enrichments map, which silently drops non-string values. `AsString` stringifies `bool` as `"true"` / `"false"`, matching existing convention. (There is no `AsBool` transform in `mapping.go`; adding one would change nothing because the enrichments map is string-keyed-string-valued.)

- [ ] **Step 6: Run the failing test again — must pass now**

Run: `go test -run TestMap_CgroupModeRegistered -v ./internal/ocsf/`
Expected: PASS.

- [ ] **Step 7: Create the golden fixture**

Run: `go test -run TestGoldens -update -v ./internal/ocsf/ 2>&1 | tail -20`

Expected: PASS for the `cgroup_mode` subtest. This writes `internal/ocsf/testdata/golden/cgroup_mode.json`.

Verify the file exists and contents look right:

```bash
cat internal/ocsf/testdata/golden/cgroup_mode.json
```

Expected: a JSON document with `"class_uid": 6005`, `"activity_id": 151`, `"app_name": "agentsh"`, `"agent_internal": true`, and an `"enrichments"` object containing `"mode": "user_namespace"`, `"reason": "no_root_cgroup_writable"`, `"own_cgroup": "/user.slice/user-1000.slice/agentsh"`, `"slice_dir": "/user.slice/user-1000.slice"`, `"io_available": "true"`, `"leaf_moved": "false"` (note: bool fields appear as quoted strings — expected, per the `map[string]string` enrichment convention).

- [ ] **Step 8: Run the full OCSF package tests**

Run: `go test ./internal/ocsf/`
Expected: PASS — all tests including TestGoldens (now without `-update`), TestMap_CgroupModeRegistered, TestExhaustiveness_AllEventTypesRegistered.

- [ ] **Step 9: Commit**

```bash
git add internal/ocsf/project_app.go internal/ocsf/mapper_test.go internal/ocsf/testdata/golden/cgroup_mode.json
git commit -m "$(cat <<'EOF'
ocsf: register cgroup_mode projector (fixes #365 startup drop)

The cgroup_mode event is emitted from internal/server/server.go on
every daemon start. It previously dropped with reason=mapper_failure
because no projector handled it. Register it in project_app.go's
infraMappings (agent_internal=true, activity_id=151) and extend
infraAllow to project the mode/own_cgroup/slice_dir/io_available/
leaf_moved fields into the enrichments map.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: AST scanner — load event constants pre-pass

**Files:**
- Modify: `internal/ocsf/exhaustiveness_test.go` (add `loadEventConstants` helper)

- [ ] **Step 1: Add the helper function**

Open `internal/ocsf/exhaustiveness_test.go`. After the `scanTypeLiterals` function (it ends around line 122 with `return out`), add this new helper:

```go
// loadEventConstants parses internal/events/types.go and returns a map
// of EventType-constant-name -> string-value (e.g.
// "EventCgroupMode" -> "cgroup_mode"). Used by scanTypeLiterals to
// resolve `Type: string(events.EventX)` and `Type: string(EventX)`
// forms — these are *ast.CallExpr conversions, not *ast.BasicLit
// strings, so the original walker missed them.
//
// The function is conservative: it only records const specs whose
// declared type is the identifier "EventType" and whose RHS is a
// single *ast.BasicLit of kind STRING. Other constants in the same
// file (or const block with no explicit type) are skipped.
func loadEventConstants(t *testing.T, rootDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	path := filepath.Join(rootDir, "internal", "events", "types.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// Require an explicit declared type named "EventType".
			typeIdent, ok := vs.Type.(*ast.Ident)
			if !ok || typeIdent.Name != "EventType" {
				continue
			}
			// Require a single BasicLit string value.
			if len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || s == "" {
				continue
			}
			out[vs.Names[0].Name] = s
		}
	}
	return out
}
```

- [ ] **Step 2: Add a unit test for the helper alone**

In the same file, after `loadEventConstants`, add:

```go
// TestLoadEventConstants_FindsEventCgroupMode verifies the const-
// resolver finds the const that motivated this work.
func TestLoadEventConstants_FindsEventCgroupMode(t *testing.T) {
	got := loadEventConstants(t, repoRoot(t))
	if got["EventCgroupMode"] != "cgroup_mode" {
		t.Errorf("EventCgroupMode -> %q, want %q", got["EventCgroupMode"], "cgroup_mode")
	}
	// Spot-check a few siblings to confirm the walker isn't accidentally
	// over-narrow.
	wantSamples := map[string]string{
		"EventCgroupMode":              "cgroup_mode",
		"EventCgroupOrphansReaped":     "cgroup_orphans_reaped",
		"EventCgroupUnavailableRefusal": "cgroup_unavailable_refusal",
	}
	for name, want := range wantSamples {
		if got[name] != want {
			t.Errorf("%s -> %q, want %q", name, got[name], want)
		}
	}
}
```

If any of the spot-check sibling constants are not actually present in `internal/events/types.go` (verify with `grep "EventCgroupOrphansReaped\|EventCgroupUnavailableRefusal" internal/events/types.go`), drop the missing entries from the `wantSamples` map. Keep `EventCgroupMode` unconditionally — it's the regression target.

- [ ] **Step 3: Run the new test**

Run: `go test -run TestLoadEventConstants_FindsEventCgroupMode -v ./internal/ocsf/`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/ocsf/exhaustiveness_test.go
git commit -m "$(cat <<'EOF'
ocsf/exhaustiveness: add loadEventConstants helper

Walks internal/events/types.go and returns the EventX -> "value"
map. Used by the AST walker (in a follow-up commit) to resolve the
`string(events.EventX)` form that the BasicLit-only walker misses.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: AST scanner — extend walker to catch `string(events.EventX)` form

**Files:**
- Modify: `internal/ocsf/exhaustiveness_test.go` (extend `scanTypeLiterals` + add tests)

- [ ] **Step 1: Add a failing test for the conversion-form detection**

In `internal/ocsf/exhaustiveness_test.go`, after the existing tests, add:

```go
// TestExhaustiveness_DetectsStringConversionForm verifies the AST
// walker recognises Type: string(events.EventX) and Type: string(EventX)
// forms — the gap that let "cgroup_mode" reach production without
// tripping TestExhaustiveness_AllEventTypesRegistered. Regression test
// for issue #365.
func TestExhaustiveness_DetectsStringConversionForm(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "qualified events.EventX in composite literal",
			src: `package x
import (
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
)
var _ = types.Event{Type: string(events.EventCgroupMode)}
`,
			want: "cgroup_mode",
		},
		{
			name: "qualified events.EventX in ev.Type assignment",
			src: `package x
import (
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/pkg/types"
)
func f(ev *types.Event) { ev.Type = string(events.EventCgroupMode) }
`,
			want: "cgroup_mode",
		},
		{
			name: "bare EventX inside events package",
			src: `package events
type EventType string
const EventCgroupMode EventType = "cgroup_mode"
type Event struct{ Type string }
var _ = Event{Type: string(EventCgroupMode)}
`,
			want: "cgroup_mode",
		},
	}
	rootDir := repoRoot(t)
	consts := loadEventConstants(t, rootDir)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := scanFromSource(t, tc.src, consts)
			if _, ok := got[tc.want]; !ok {
				t.Fatalf("scanner did not find %q in %s; found = %v", tc.want, tc.name, keysOf(got))
			}
		})
	}
}

// TestExhaustiveness_DoesNotOverDetect verifies non-string-conversion
// references (e.g. a bare events.EventX used as a value, not wrapped
// in `string(...)`) are NOT recorded by the conversion-form branch.
func TestExhaustiveness_DoesNotOverDetect(t *testing.T) {
	src := `package x
import "github.com/agentsh/agentsh/internal/events"
var _ = events.EventCgroupMode
`
	consts := loadEventConstants(t, repoRoot(t))
	got := scanFromSource(t, src, consts)
	if _, ok := got["cgroup_mode"]; ok {
		t.Fatalf("scanner over-detected cgroup_mode from a bare reference; found = %v", keysOf(got))
	}
}

// scanFromSource is a test helper that runs the walker over a single
// in-memory source string. It mirrors scanTypeLiterals' AST walk but
// against a string rather than disk.
func scanFromSource(t *testing.T, src string, consts map[string]string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "in_memory.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse in-memory source: %v", err)
	}
	out := map[string]string{}
	walkEventTypeLiterals(f, fset, consts, out)
	return out
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

These tests will not compile yet because `walkEventTypeLiterals` doesn't exist — Step 2 extracts it.

- [ ] **Step 2: Extract `walkEventTypeLiterals` so the walker is reusable**

Open `internal/ocsf/exhaustiveness_test.go`. Find `scanTypeLiterals`. Refactor its inner `ast.Inspect(f, ...)` body into a new top-level helper:

```go
// walkEventTypeLiterals walks an already-parsed *ast.File and records
// every event Type literal found into `out` (keyed by string value,
// valued by position string). Pulled out of scanTypeLiterals so the
// CallExpr branch can be unit-tested against in-memory sources.
func walkEventTypeLiterals(f *ast.File, fset *token.FileSet, consts map[string]string, out map[string]string) {
	addLit := func(s string, pos token.Pos) {
		if s == "" {
			return
		}
		if _, seen := out[s]; !seen {
			out[s] = fset.Position(pos).String()
		}
	}
	// resolveCall returns the string value the call expression resolves
	// to, if it is `string(events.EventX)` or `string(EventX)` and EventX
	// is in consts. Returns ("", false) otherwise.
	resolveCall := func(call *ast.CallExpr) (string, bool) {
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "string" {
			return "", false
		}
		if len(call.Args) != 1 {
			return "", false
		}
		switch arg := call.Args[0].(type) {
		case *ast.SelectorExpr:
			// Qualified: events.EventX
			pkgIdent, ok := arg.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "events" {
				return "", false
			}
			if v, ok := consts[arg.Sel.Name]; ok {
				return v, true
			}
		case *ast.Ident:
			// Bare: EventX (same-package use)
			if v, ok := consts[arg.Name]; ok {
				return v, true
			}
		}
		return "", false
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if !isEventCompositeLit(x) {
				return true
			}
			for _, elt := range x.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				ident, ok := kv.Key.(*ast.Ident)
				if !ok || ident.Name != "Type" {
					continue
				}
				switch v := kv.Value.(type) {
				case *ast.BasicLit:
					if v.Kind == token.STRING {
						if s, err := strconv.Unquote(v.Value); err == nil {
							addLit(s, v.Pos())
						}
					}
				case *ast.CallExpr:
					if s, ok := resolveCall(v); ok {
						addLit(s, v.Pos())
					}
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) != 1 || len(x.Rhs) != 1 {
				return true
			}
			sel, ok := x.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Type" {
				return true
			}
			switch v := x.Rhs[0].(type) {
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					if s, err := strconv.Unquote(v.Value); err == nil {
						addLit(s, v.Pos())
					}
				}
			case *ast.CallExpr:
				if s, ok := resolveCall(v); ok {
					addLit(s, v.Pos())
				}
			}
		}
		return true
	})
}
```

Now replace the body of `scanTypeLiterals`'s `ast.Inspect(f, func(n ast.Node) bool { ... })` call with a single call to the new helper. The full body of `scanTypeLiterals` should become roughly:

```go
func scanTypeLiterals(t *testing.T, rootDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	consts := loadEventConstants(t, rootDir)
	skip := map[string]bool{
		"vendor": true, ".gomodcache": true, "build": true, "bin": true, "dist": true,
		"node_modules": true, ".git": true, ".claude": true, "tmp": true, "examples": true,
	}
	walkErr := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Logf("parse %s: %v (skipping)", path, err)
			return nil
		}
		walkEventTypeLiterals(f, fset, consts, out)
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk: %v", walkErr)
	}
	return out
}
```

(Verify the exact surrounding code by reading the current file first; the variable names `skip`, `walkErr`, and the `parser.SkipObjectResolution` call must remain identical to the original. The only structural change is: removing the inline `ast.Inspect` block, calling `walkEventTypeLiterals` in its place, and adding the `consts := loadEventConstants(t, rootDir)` line at the top.)

- [ ] **Step 3: Run all the new tests**

Run: `go test -run 'TestExhaustiveness_DetectsStringConversionForm|TestExhaustiveness_DoesNotOverDetect|TestLoadEventConstants' -v ./internal/ocsf/`

Expected: all three PASS.

- [ ] **Step 4: Run the full exhaustiveness test — must still pass**

Run: `go test -run TestExhaustiveness -v ./internal/ocsf/`

Expected: `TestExhaustiveness_AllEventTypesRegistered` PASS, `TestExhaustiveness_PendingTypesShrinking` PASS, plus the new detection tests PASS. Because `cgroup_mode` is now registered (Task 2), the scanner discovering it via the conversion-form branch will find a registered entry — green.

- [ ] **Step 5: Negative-regression verification (local-only, do not commit the revert)**

To prove the scanner now catches the gap, temporarily revert Task 2's projector registration:

```bash
git stash push internal/ocsf/project_app.go
```

Run: `go test -run TestExhaustiveness_AllEventTypesRegistered -v ./internal/ocsf/`

Expected: FAIL with output naming `cgroup_mode` and the source position `internal/server/server.go:492` (or wherever the `string(events.EventCgroupMode)` call sits).

Restore Task 2:

```bash
git stash pop
```

Run: `go test -run TestExhaustiveness_AllEventTypesRegistered -v ./internal/ocsf/`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/ocsf/exhaustiveness_test.go
git commit -m "$(cat <<'EOF'
ocsf/exhaustiveness: detect Type: string(events.EventX) form

The AST walker previously matched only *ast.BasicLit values, missing
the `Type: string(events.EventCgroupMode)` form used at
internal/server/server.go:492 (and any future call sites that go
through the EventType conversion). This is why cgroup_mode reached
production without tripping TestExhaustiveness_AllEventTypesRegistered.

Add a pre-pass over internal/events/types.go that builds an
EventX -> "value" map, then teach the walker to recognise
*ast.CallExpr conversions of form `string(events.EventX)` (qualified)
and `string(EventX)` (bare, same-package).

Refs #365.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Add `agent_id` field to `AuditWatchtowerConfig`

**Files:**
- Modify: `internal/config/config.go` (add `AgentID` field to `AuditWatchtowerConfig`)
- Modify: `internal/config/config_test.go` (round-trip test)

- [ ] **Step 1: Add a failing round-trip test**

Open `internal/config/config_test.go`. Locate `TestAuditWatchtowerConfig_DefaultsExpand` (around line 1618) to confirm the existing YAML-load test pattern. Below it, add this new test (use the same package name, imports, and helpers as the surrounding tests):

```go
// TestAuditWatchtowerConfig_AgentIDRoundtrip verifies the new
// audit.watchtower.agent_id YAML field survives load. Regression test
// for issue #365 (Phase 1 wiring: agent_id was hardcoded to hostname).
func TestAuditWatchtowerConfig_AgentIDRoundtrip(t *testing.T) {
	yaml := []byte(`
audit:
  watchtower:
    enabled: true
    endpoint: "localhost:9090"
    agent_id: "agent-edge-001"
    tls:
      insecure: true
    auth:
      token_env: "AGENTSH_TEST_TOKEN"
    chain:
      algorithm: hmac-sha256
      key_source: env
      key_env: AGENTSH_TEST_CHAIN_KEY
`)
	cfg, err := loadFromBytes(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Audit.Watchtower.AgentID; got != "agent-edge-001" {
		t.Errorf("AgentID = %q, want %q", got, "agent-edge-001")
	}
}

// TestAuditWatchtowerConfig_AgentIDOptional verifies omitting the
// field gives the zero string — the buildWatchtowerStore-side
// hostname-fallback is exercised in internal/server tests.
func TestAuditWatchtowerConfig_AgentIDOptional(t *testing.T) {
	yaml := []byte(`
audit:
  watchtower:
    enabled: true
    endpoint: "localhost:9090"
    tls:
      insecure: true
    auth:
      token_env: "AGENTSH_TEST_TOKEN"
    chain:
      algorithm: hmac-sha256
      key_source: env
      key_env: AGENTSH_TEST_CHAIN_KEY
`)
	cfg, err := loadFromBytes(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Audit.Watchtower.AgentID; got != "" {
		t.Errorf("AgentID = %q, want empty (omitted)", got)
	}
}
```

The helper `loadFromBytes(t, yaml) (*Config, error)` may not exist under that exact name in `config_test.go` — check the file. If a different helper is used (e.g. `mustLoadYAML`, `decodeYAML`, or a `t.TempDir()` + write-file pattern), reuse whatever the existing `TestAuditWatchtowerConfig_DefaultsExpand` uses. Mirror that helper exactly. Do NOT introduce a new helper.

If no such helper exists, follow this fallback pattern (which writes the YAML to a temp file and calls the package's `Load` function — replace `Load` with whatever the test file already imports):

```go
func TestAuditWatchtowerConfig_AgentIDRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil { t.Fatal(err) }
	cfg, err := Load(path)
	if err != nil { t.Fatalf("load: %v", err) }
	if got := cfg.Audit.Watchtower.AgentID; got != "agent-edge-001" {
		t.Errorf("AgentID = %q, want %q", got, "agent-edge-001")
	}
}
```

- [ ] **Step 2: Run the new tests to verify they fail at compile time**

Run: `go test -run 'TestAuditWatchtowerConfig_AgentID' -v ./internal/config/`

Expected: build failure with `cfg.Audit.Watchtower.AgentID undefined (type AuditWatchtowerConfig has no field or method AgentID)`. Confirms TDD red.

- [ ] **Step 3: Add the field**

Open `internal/config/config.go`. Find the `AuditWatchtowerConfig` struct definition (around line 885). Find the existing `SessionID` field (around line 888):

```go
SessionID     string `yaml:"session_id"` // optional; auto-generated ULID if empty
```

Immediately after that line, insert:

```go
	// AgentID is the operator-visible identifier for this agent on the
	// Watchtower wire. When empty (the default), buildWatchtowerStore
	// falls back to os.Hostname() — preserving pre-existing behaviour
	// from before this field existed.
	//
	// Mirrors SessionID: optional in YAML, resolved at store-construction
	// time (NOT in applyDefaults — non-daemon CLI subcommands like
	// `agentsh config show` must not trigger hostname lookup).
	AgentID string `yaml:"agent_id"`
```

Do NOT add anything to `applyDefaults` or `validate`. The empty string is a legitimate sentinel meaning "fall back to hostname".

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `go test -run 'TestAuditWatchtowerConfig_AgentID' -v ./internal/config/`

Expected: both PASS.

- [ ] **Step 5: Run the full config test package**

Run: `go test ./internal/config/`

Expected: PASS. No existing test exercises a field at the position we inserted at; pointer-based field layout is irrelevant.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "$(cat <<'EOF'
config: add audit.watchtower.agent_id field

Operator-visible identifier for this agent on the Watchtower wire.
Optional; empty value means buildWatchtowerStore falls back to
os.Hostname() (preserving pre-existing behaviour).

Resolved at store-construction time, not in applyDefaults, mirroring
how SessionID is handled.

Refs #365.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Wire `agent_id` resolution in `buildWatchtowerStore`

**Files:**
- Modify: `internal/server/wtp.go` (add private `resolveAgentID` + export `ResolveAgentIDForTest`)
- Modify: `internal/server/wtp_test.go` (three new resolution test cases)

- [ ] **Step 1: Add a failing test for the export**

Open `internal/server/wtp_test.go`. After the last existing test, add the three new resolution tests:

```go
// TestResolveAgentID_ExplicitOverride verifies the config field takes
// precedence over os.Hostname(). Regression test for issue #365.
func TestResolveAgentID_ExplicitOverride(t *testing.T) {
	cfg := config.AuditWatchtowerConfig{AgentID: "agent-edge-001"}
	got := server.ResolveAgentIDForTest(cfg)
	if got != "agent-edge-001" {
		t.Errorf("ResolveAgentIDForTest = %q, want %q", got, "agent-edge-001")
	}
}

// TestResolveAgentID_EmptyFallsBackToHostname verifies the empty
// string triggers the os.Hostname() fallback.
func TestResolveAgentID_EmptyFallsBackToHostname(t *testing.T) {
	cfg := config.AuditWatchtowerConfig{AgentID: ""}
	got := server.ResolveAgentIDForTest(cfg)
	hostname, _ := os.Hostname()
	// Accept either the host name (normal path) or "unknown" (Hostname
	// returned an error). Both are documented behaviours.
	if got == "" {
		t.Errorf("ResolveAgentIDForTest returned empty; want hostname (%q) or \"unknown\"", hostname)
	}
	if hostname != "" && got != hostname {
		t.Errorf("ResolveAgentIDForTest = %q, want %q (os.Hostname)", got, hostname)
	}
}

// TestResolveAgentID_WhitespaceTreatedAsEmpty verifies whitespace-only
// values fall back to the hostname.
func TestResolveAgentID_WhitespaceTreatedAsEmpty(t *testing.T) {
	cfg := config.AuditWatchtowerConfig{AgentID: "   "}
	got := server.ResolveAgentIDForTest(cfg)
	hostname, _ := os.Hostname()
	if hostname != "" && got != hostname {
		t.Errorf("ResolveAgentIDForTest(whitespace) = %q, want hostname %q", got, hostname)
	}
}

// TestResolveAgentID_TrimsLeadingTrailingWhitespace verifies a
// well-formed-but-padded value is trimmed before use.
func TestResolveAgentID_TrimsLeadingTrailingWhitespace(t *testing.T) {
	cfg := config.AuditWatchtowerConfig{AgentID: "  agent-x  "}
	got := server.ResolveAgentIDForTest(cfg)
	if got != "agent-x" {
		t.Errorf("ResolveAgentIDForTest = %q, want %q (trimmed)", got, "agent-x")
	}
}
```

Verify the existing `import` block in `wtp_test.go` includes `"os"`. If not, add it.

- [ ] **Step 2: Run the new tests to verify they fail at compile time**

Run: `go test -run TestResolveAgentID -v ./internal/server/`

Expected: build failure with `undefined: server.ResolveAgentIDForTest`. Confirms TDD red.

- [ ] **Step 3: Add the private resolver and test export**

Open `internal/server/wtp.go`. Find the existing `resolveLogGoawayMessage` function (around line 32 — it has a similar shape: small, pure function for store-construction-time config resolution). Below it (or below the `ResolveLogGoawayMessageForTest` near the bottom — match whatever organisational style the file uses; the helpers cluster), add:

```go
// resolveAgentID returns the agent identifier the WTP store should
// advertise on the wire. Precedence:
//
//  1. TrimSpace(cfg.AgentID) if non-empty.
//  2. os.Hostname() if it succeeds.
//  3. "unknown" as a last-resort sentinel — matches the prior behaviour
//     for the Hostname-error case.
//
// This is called from buildWatchtowerStore. Keeping it as a small
// pure function lets us unit-test the three rungs independently of
// the surrounding KMS/transport machinery.
func resolveAgentID(cfg config.AuditWatchtowerConfig) string {
	id := strings.TrimSpace(cfg.AgentID)
	if id != "" {
		return id
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
```

Confirm the file's import block already contains `"os"` and `"strings"`. Both are imported per the file head; no import-block edit needed.

Then, near the bottom of the file (next to `ResolveAuthBearerForTest` and `ResolveLogGoawayMessageForTest`), add:

```go
// ResolveAgentIDForTest is a thin export of resolveAgentID for unit
// tests. Production callers use the unexported resolveAgentID inline
// in buildWatchtowerStore.
func ResolveAgentIDForTest(cfg config.AuditWatchtowerConfig) string {
	return resolveAgentID(cfg)
}
```

- [ ] **Step 4: Replace the inline resolution in `buildWatchtowerStore`**

In the same file, find the block (around lines 89–93):

```go
	// AgentID is not in AuditWatchtowerConfig (Phase 1 gap); derive from hostname.
	agentID, err := os.Hostname()
	if err != nil {
		agentID = "unknown"
	}
```

Replace it with:

```go
	agentID := resolveAgentID(cfg)
```

Also update the `buildWatchtowerStore` doc comment block (lines 54–56 area): the existing comment reads:

```go
// AgentID: derived from os.Hostname() when not overridable from config
// (AuditWatchtowerConfig carries no explicit agent_id field in Phase 1).
// This gives a stable, human-readable per-host identity.
```

Replace it with:

```go
// AgentID: cfg.AgentID takes precedence; empty/whitespace-only falls
// back to os.Hostname(); a Hostname() error falls back to "unknown".
// See resolveAgentID.
```

- [ ] **Step 5: Run the new tests — must pass**

Run: `go test -run TestResolveAgentID -v ./internal/server/`

Expected: all four PASS.

- [ ] **Step 6: Run the broader server tests**

Run: `go test ./internal/server/`

Expected: PASS — the existing `TestBuildWatchtowerStore_*` tests are unaffected (they exercise the disabled-store / KMS-error / SessionID-autogen paths, none of which the AgentID change touches).

- [ ] **Step 7: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: clean build. `os.Hostname()` is cross-platform; the change introduces no platform-specific code.

- [ ] **Step 8: Commit**

```bash
git add internal/server/wtp.go internal/server/wtp_test.go
git commit -m "$(cat <<'EOF'
server/wtp: resolve agent_id from config with hostname fallback

Closes the Phase 1 gap noted at internal/server/wtp.go:90. Operators
can now set audit.watchtower.agent_id to bind the agent to a
Watchtower-provisioned agent_id without renaming the host.

Resolution order:
  1. TrimSpace(cfg.AgentID) if non-empty
  2. os.Hostname()
  3. "unknown" (Hostname error fallback)

Refactor the inline block into a pure resolveAgentID(cfg) helper,
matching the existing resolveLogGoawayMessage pattern. Export
ResolveAgentIDForTest for unit tests.

Refs #365.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Full repo verification

- [ ] **Step 1: Full test pass**

Run: `go test ./...`
Expected: PASS for every package. Allow whatever pre-existing flaky tests are documented (e.g. `TestFlushLoop_PeriodicSync` on Windows — see `~/.claude/projects/-home-eran-work-agentsh/memory/project_flushloop_windows_flake.md`). The packages touched by this work — `internal/ocsf`, `internal/config`, `internal/server` — must all pass cleanly.

- [ ] **Step 2: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: clean build.

- [ ] **Step 3: Lint (if a linter is wired in)**

Run: `go vet ./...`
Expected: no findings. (If the repo has additional tooling — `golangci-lint`, etc. — run whichever invocation is documented in `AGENTS.md` or `CLAUDE.md`.)

- [ ] **Step 4: Confirm no leftover stash, no uncommitted files**

Run: `git status`
Expected: clean working tree on the feature branch with seven commits (Task 1 const, Task 2 projector + goldens, Task 3 helper, Task 4 walker, Task 5 config field, Task 6 wtp wiring) — Task 7 produces no commit if nothing is left.

- [ ] **Step 5: Verify all three acceptance criteria via test reads**

Acceptance check 1 (cgroup_mode no longer drops):
```bash
go test -run 'TestMap_CgroupModeRegistered|TestGoldens/cgroup_mode' -v ./internal/ocsf/
```
Expected: both PASS.

Acceptance check 2 (agent_id resolves correctly):
```bash
go test -run TestResolveAgentID -v ./internal/server/
```
Expected: all four PASS.

Acceptance check 3 (scanner now catches conversion form):
```bash
go test -run 'TestExhaustiveness_DetectsStringConversionForm|TestExhaustiveness_AllEventTypesRegistered' -v ./internal/ocsf/
```
Expected: both PASS. (Manual negative-regression verification was done in Task 4 Step 5.)

---

### Task 8 (optional): Manual demo smoke

The automated tests are the source of truth. This task is for an operator confirmation against a live Watchtower instance. Skip if no demo stack is at hand.

- [ ] **Step 1: Rebuild the daemon**

Run: `go build -o bin/agentsh ./cmd/agentsh`
Expected: clean build.

- [ ] **Step 2: Update the demo config**

Add to the config from issue #365:

```yaml
audit:
  watchtower:
    enabled: true
    endpoint: "localhost:9090"
    agent_id: "agent-edge-001"   # NEW
    tls: { insecure: true }
    auth: { token_file: ~/.config/agentsh/wtp-token }
    chain:
      algorithm: hmac-sha256
      key_source: file
      key_file: ~/.config/agentsh/wtp-chain.key
```

- [ ] **Step 3: Start the daemon and verify logs**

Run: `./bin/agentsh ...` (use whatever invocation the smoke test in issue #365 used).

Expected: startup logs contain **zero** `wtp: dropping event before WAL append reason=mapper_failure err="...:\"cgroup_mode\""` lines. If the line is still present, the projector registration did not load — re-run `go test ./internal/ocsf/` to confirm registration.

- [ ] **Step 4: Verify Watchtower-side identity**

On the Watchtower side, confirm the incoming stream's Hello carries `agent_id=agent-edge-001`. If it still shows the hostname, the config field was not loaded — `cat /path/to/config.yaml | grep agent_id` and re-confirm.

---

## Out-of-scope follow-ups (not part of this plan)

- `db_statement` projector (the only remaining true `pendingTypes` entry).
- "Exec events not visible on Watchtower" investigation — separate bug, not caused by the OCSF mapper.
- AST scanner helper-emitter walker upgrade (TODO at `internal/ocsf/exhaustiveness_test.go:36`).

These are listed in the spec's "Out-of-scope follow-ups" section.
