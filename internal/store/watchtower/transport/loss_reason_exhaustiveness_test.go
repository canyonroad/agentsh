package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestToWireReason_Exhaustive enforces that every wal.LossReason*
// constant has a matching `case wal.LossReason*` clause in
// ToWireReason. Adding a new constant without updating ToWireReason
// would fall through to the UNSPECIFIED default, dropping the marker
// at the carrier — silent integrity gap. This AST walker fails CI in
// that scenario.
func TestToWireReason_Exhaustive(t *testing.T) {
	thisFile := callerFile(t)
	transportDir := filepath.Dir(thisFile)
	walDir := filepath.Join(transportDir, "..", "wal")

	walConsts := collectLossReasonConstants(t, filepath.Join(walDir, "loss_reasons.go"))
	cases := collectToWireReasonCases(t, filepath.Join(transportDir, "loss_reason.go"))

	for _, name := range walConsts {
		want := "wal." + name
		found := false
		for _, c := range cases {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ToWireReason missing case for %s — would silently drop loss markers with that reason", want)
		}
	}
}

func collectLossReasonConstants(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, ident := range vs.Names {
				if strings.HasPrefix(ident.Name, "LossReason") {
					names = append(names, ident.Name)
				}
			}
		}
		return true
	})
	if len(names) == 0 {
		t.Fatalf("no LossReason* constants found in %s", path)
	}
	return names
}

func collectToWireReasonCases(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var cases []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ToWireReason" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range cc.List {
				sel, ok := expr.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					continue
				}
				cases = append(cases, pkg.Name+"."+sel.Sel.Name)
			}
			return true
		})
		return false
	})
	return cases
}

func callerFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return file
}
