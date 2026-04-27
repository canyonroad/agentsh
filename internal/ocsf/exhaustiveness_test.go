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

// scanTypeLiterals walks rootDir for .go files (excluding vendor/,
// .gomodcache/, build/, bin/, dist/, etc.) and collects every string
// literal passed as the Type field of a types.Event composite literal
// or assigned to ev.Type.
//
// LIMITATION: the AST walker matches only literal `Type: "..."` or
// `ev.Type = "..."` assignments. Emitters that call a helper function
// and then assign its return value — for example:
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
					if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, err := strconv.Unquote(lit.Value)
						if err == nil && s != "" {
							pos := fset.Position(lit.Pos())
							if _, seen := out[s]; !seen {
								out[s] = pos.String()
							}
						}
					}
				}
			case *ast.AssignStmt:
				// ev.Type = "foo"
				if len(x.Lhs) != 1 || len(x.Rhs) != 1 {
					return true
				}
				sel, ok := x.Lhs[0].(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Type" {
					return true
				}
				if lit, ok := x.Rhs[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, err := strconv.Unquote(lit.Value)
					if err == nil && s != "" {
						pos := fset.Position(lit.Pos())
						if _, seen := out[s]; !seen {
							out[s] = pos.String()
						}
					}
				}
			}
			return true
		})
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
