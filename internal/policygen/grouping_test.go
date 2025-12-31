// internal/policygen/grouping_test.go
package policygen

import "testing"

func TestGroupPaths_ThresholdCollapse(t *testing.T) {
	paths := []string{
		"/workspace/src/a.ts",
		"/workspace/src/b.ts",
		"/workspace/src/c.ts",
		"/workspace/src/d.ts",
		"/workspace/src/e.ts",
		"/workspace/src/f.ts",
	}

	groups := GroupPaths(paths, 5)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Pattern != "/workspace/src/**" {
		t.Errorf("expected pattern '/workspace/src/**', got %q", groups[0].Pattern)
	}
}

func TestGroupPaths_BelowThreshold(t *testing.T) {
	paths := []string{
		"/workspace/src/a.ts",
		"/workspace/src/b.ts",
	}

	groups := GroupPaths(paths, 5)

	// Below threshold, keep individual paths
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}

func TestGroupPaths_CommonPrefix(t *testing.T) {
	paths := []string{
		"/workspace/node_modules/lodash/index.js",
		"/workspace/node_modules/lodash/fp.js",
		"/workspace/node_modules/express/index.js",
		"/workspace/node_modules/express/router.js",
		"/workspace/node_modules/axios/index.js",
		"/workspace/node_modules/axios/lib/core.js",
	}

	groups := GroupPaths(paths, 3)

	// Should collapse to /workspace/node_modules/**
	if len(groups) != 1 {
		t.Fatalf("expected 1 group after prefix collapse, got %d: %+v", len(groups), groups)
	}
	if groups[0].Pattern != "/workspace/node_modules/**" {
		t.Errorf("expected '/workspace/node_modules/**', got %q", groups[0].Pattern)
	}
}

func TestGroupDomains_WildcardCollapse(t *testing.T) {
	domains := []string{
		"api.github.com",
		"raw.github.com",
		"gist.github.com",
	}

	groups := GroupDomains(domains)

	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Pattern != "*.github.com" {
		t.Errorf("expected '*.github.com', got %q", groups[0].Pattern)
	}
}

func TestGroupDomains_NoCollapse(t *testing.T) {
	domains := []string{
		"api.github.com",
		"registry.npmjs.org",
	}

	groups := GroupDomains(domains)

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
}
