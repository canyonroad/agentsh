package pkgcheck

import (
	"testing"
)

func TestPrivacyFilter_PrivateRegistryAutoDetect(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org", "pypi.org"},
	})
	in := []PackageRef{
		{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org"},
		{Name: "internal-tool", Version: "0.1.0", Registry: "artifactory.acme.local"},
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || scan[0].Name != "lodash" {
		t.Fatalf("scan = %+v, want lodash only", scan)
	}
	if len(skip) != 1 || skip[0].Reason != SkipReasonPrivateRegistry {
		t.Fatalf("skip = %+v, want internal-tool with private_registry", skip)
	}
}

func TestPrivacyFilter_ScopeDenylist(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
		PrivateScopeDenylist:   []string{"@acme", "@internal-*"},
	})
	in := []PackageRef{
		{Name: "@acme/billing", Version: "1.0.0", Registry: "registry.npmjs.org"},
		{Name: "@internal-platform/utils", Version: "1.0.0", Registry: "registry.npmjs.org"},
		{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org"},
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || scan[0].Name != "lodash" {
		t.Fatalf("scan = %+v, want lodash only", scan)
	}
	if len(skip) != 2 {
		t.Fatalf("skip = %+v, want 2 entries", skip)
	}
	for _, s := range skip {
		if s.Reason != SkipReasonPrivateScopeDenylist {
			t.Errorf("want denylist reason for %s, got %s", s.Package.Name, s.Reason)
		}
	}
}

func TestPrivacyFilter_EmptyAllowlistTreatsAllAsPublic(t *testing.T) {
	// An empty allowlist means "no registry filter applied" — defer to denylist only.
	pf := NewPrivacyFilter(PrivacyConfig{})
	in := []PackageRef{{Name: "lodash", Version: "4.17.21", Registry: "anything"}}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || len(skip) != 0 {
		t.Fatalf("scan=%v skip=%v", scan, skip)
	}
}

func TestPrivacyFilter_RegistryRuleTakesPriority(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
		PrivateScopeDenylist:   []string{"@acme"},
	})
	// On a private registry — should report private_registry, not denylist.
	in := []PackageRef{{Name: "@acme/x", Version: "1", Registry: "artifactory.acme.local"}}
	_, skip := pf.Partition(in)
	if len(skip) != 1 || skip[0].Reason != SkipReasonPrivateRegistry {
		t.Fatalf("want private_registry, got %+v", skip)
	}
}

func TestPrivacyFilter_EmptyRegistryFailsClosed(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
	})
	in := []PackageRef{
		{Name: "lodash", Version: "4.17.21", Registry: ""}, // resolver did not populate Registry
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 0 {
		t.Errorf("empty Registry must not bypass the allowlist; scan=%+v", scan)
	}
	if len(skip) != 1 || skip[0].Reason != SkipReasonPrivateRegistry {
		t.Errorf("want skip with private_registry reason; got %+v", skip)
	}
}

func TestPrivacyFilter_EmptyDenylistPatternIsIgnored(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		PrivateScopeDenylist: []string{""},
	})
	in := []PackageRef{{Name: "lodash", Version: "1"}}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || len(skip) != 0 {
		t.Errorf("empty pattern must not match anything; scan=%v skip=%v", scan, skip)
	}
}

func TestPrivacyFilter_DenylistMatchesUnscopedPrefix(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		PrivateScopeDenylist: []string{"internal-"},
	})
	in := []PackageRef{
		{Name: "internal-tool", Version: "1"},
		{Name: "internal-foo", Version: "1"},
		{Name: "external-thing", Version: "1"},
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || scan[0].Name != "external-thing" {
		t.Fatalf("scan = %+v, want external-thing only", scan)
	}
	if len(skip) != 2 {
		t.Fatalf("skip = %+v, want 2 entries", skip)
	}
	for _, s := range skip {
		if s.Reason != SkipReasonPrivateScopeDenylist {
			t.Errorf("want denylist reason for %s, got %s", s.Package.Name, s.Reason)
		}
	}
}

func TestPrivacyFilter_NormalizesRegistryURLs(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
	})
	in := []PackageRef{
		{Name: "lodash", Version: "1", Registry: "https://registry.npmjs.org/"},
		{Name: "express", Version: "1", Registry: "registry.npmjs.org"},
		{Name: "react", Version: "1", Registry: "REGISTRY.NPMJS.ORG"},
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 3 {
		t.Errorf("all three URL forms should match the allowlist; scan=%v skip=%v", scan, skip)
	}
}

func TestNormalizeRegistry(t *testing.T) {
	cases := map[string]string{
		"registry.npmjs.org":             "registry.npmjs.org",
		"https://registry.npmjs.org/":    "registry.npmjs.org",
		"https://registry.npmjs.org":     "registry.npmjs.org",
		"http://Registry.NPMJS.org/path": "registry.npmjs.org/path",
		"https://artifact.example/team-a/": "artifact.example/team-a",
		"":                               "",
	}
	for in, want := range cases {
		if got := normalizeRegistry(in); got != want {
			t.Errorf("normalizeRegistry(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestPrivacyFilter_PathDistinguishesRegistries(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"https://artifact.example/team-a/"},
	})
	in := []PackageRef{
		{Name: "x", Registry: "https://artifact.example/team-a/"}, // allowed
		{Name: "y", Registry: "https://artifact.example/team-b/"}, // private — different path
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || scan[0].Name != "x" {
		t.Errorf("only team-a should be allowed; scan=%v skip=%v", scan, skip)
	}
	if len(skip) != 1 || skip[0].Package.Name != "y" || skip[0].Reason != SkipReasonPrivateRegistry {
		t.Errorf("team-b should be skipped with private_registry; skip=%v", skip)
	}
}

func TestPrivacyFilter_DefaultsAllowPyPISimpleIndex(t *testing.T) {
	// Mirror of the production default allowlist. The pip-default index URL
	// `https://pypi.org/simple/` must match so explicit --index-url on
	// public PyPI doesn't get skipped.
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org", "pypi.org", "pypi.org/simple"},
	})
	in := []PackageRef{
		{Name: "lodash", Version: "1", Registry: "registry.npmjs.org"},
		{Name: "requests", Version: "1", Registry: "pypi.org"},
		{Name: "flask", Version: "1", Registry: "https://pypi.org/simple/"},
		{Name: "django", Version: "1", Registry: "https://pypi.org/simple"},
	}
	scan, skip := pf.Partition(in)
	if len(skip) != 0 {
		t.Errorf("all four public-registry forms should match; skip=%+v", skip)
	}
	if len(scan) != 4 {
		t.Errorf("want 4 scanned; got %d", len(scan))
	}
}
