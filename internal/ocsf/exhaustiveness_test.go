package ocsf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

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

// scanTypeLiterals walks rootDir for .go files (excluding vendor/,
// .gomodcache/, build/, bin/, dist/, etc.) and collects every string
// literal passed as the Type field of a types.Event composite literal
// or assigned to ev.Type.
//
// LIMITATION: the AST walker matches only literal `Type: "..."` or
// `ev.Type = "..."` assignments, plus `Type: string(events.EventX)`
// conversions. Emitters that call a helper function and then assign
// its return value — for example:
//
//	n.emitFileEvent(ctx, "dir_list", ...)
//
// are NOT auto-detected because the string literal is an argument to a
// function call rather than a direct assignment to a Type field. Such
// types must be registered manually in the appropriate project_*.go
// file. Known helper-based emit sites (as of roborev #6346):
//
//	internal/netmonitor/proxy.go:252          — "net_close"
//	internal/netmonitor/transparent_tcp.go:141 — "net_close"
//	internal/fsmonitor/fuse.go:236-325        — "dir_list", "file_stat",
//	                                            "dir_create", "dir_delete",
//	                                            "symlink_create", "symlink_read"
//
// TODO: extend the walker to follow helper-based emitters using go/types.
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
		// Exclude generated *.pb.go (protoc output) — never contain ev.Type literals.
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

// isEventCompositeLit returns true if c looks like a composite literal
// constructing a `types.Event` (or any package-qualified `Event`). False
// positives are tolerable; missed positives are not.
func isEventCompositeLit(c *ast.CompositeLit) bool {
	switch t := c.Type.(type) {
	case *ast.SelectorExpr:
		return t.Sel != nil && t.Sel.Name == "Event"
	case *ast.Ident:
		return t.Name == "Event"
	}
	return false
}

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

// TestExhaustiveness_AllEventTypesRegistered walks the source tree and
// asserts every distinct ev.Type string literal is in registry,
// pendingTypes, or skiplist. Reports the file:line of the first
// occurrence on failure.
func TestExhaustiveness_AllEventTypesRegistered(t *testing.T) {
	root := repoRoot(t)
	found := scanTypeLiterals(t, root)
	var missing []string
	for s, pos := range found {
		if _, ok := registry[s]; ok {
			continue
		}
		if _, ok := pendingTypes[s]; ok {
			continue
		}
		if _, ok := skiplist[s]; ok {
			continue
		}
		missing = append(missing, s+" (first seen "+pos+")")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("event Type literals not registered, pending, or skiplisted:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// TestExhaustiveness_PendingTypesShrinking is a hint test — when
// pendingTypes is empty, Phase 1's catalog is functionally complete.
// Logs a confirmation; does not fail. The real coverage is the
// exhaustiveness test above.
func TestExhaustiveness_PendingTypesShrinking(t *testing.T) {
	if len(pendingTypes) == 0 {
		t.Log("pendingTypes is empty — Phase 1 catalog complete")
	}
}

// repoRoot returns the agentsh repo root via go.mod search starting
// from this file's directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for {
		entries, err := filepath.Glob(filepath.Join(dir, "go.mod"))
		if err == nil && len(entries) == 1 {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repoRoot: go.mod not found")
		}
		dir = parent
	}
}

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
