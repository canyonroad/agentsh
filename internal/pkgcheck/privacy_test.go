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
