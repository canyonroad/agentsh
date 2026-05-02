package pkgcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageRef_String(t *testing.T) {
	tests := []struct {
		name string
		ref  PackageRef
		want string
	}{
		{
			name: "name only",
			ref:  PackageRef{Name: "lodash"},
			want: "lodash",
		},
		{
			name: "name with version",
			ref:  PackageRef{Name: "lodash", Version: "4.17.21"},
			want: "lodash@4.17.21",
		},
		{
			name: "scoped npm package",
			ref:  PackageRef{Name: "@types/node", Version: "20.0.0"},
			want: "@types/node@20.0.0",
		},
		{
			name: "empty version returns name only",
			ref:  PackageRef{Name: "requests", Version: ""},
			want: "requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ref.String())
		})
	}
}

func TestSeverity_Weight(t *testing.T) {
	// Verify ordering: critical > high > medium > low > info
	weights := []struct {
		severity Severity
		weight   int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityInfo, 0},
	}

	for _, w := range weights {
		t.Run(string(w.severity), func(t *testing.T) {
			assert.Equal(t, w.weight, w.severity.Weight())
		})
	}

	// Verify strict ordering
	assert.Greater(t, SeverityCritical.Weight(), SeverityHigh.Weight())
	assert.Greater(t, SeverityHigh.Weight(), SeverityMedium.Weight())
	assert.Greater(t, SeverityMedium.Weight(), SeverityLow.Weight())
	assert.Greater(t, SeverityLow.Weight(), SeverityInfo.Weight())
}

func TestSeverity_Weight_Unknown(t *testing.T) {
	unknown := Severity("unknown")
	assert.Equal(t, 5, unknown.Weight(), "unknown severity should fail closed with weight > critical")
}

func TestVerdictAction_Weight_Unknown(t *testing.T) {
	unknown := VerdictAction("unknown")
	assert.Equal(t, 4, unknown.weight(), "unknown action should fail closed with weight > block")
}

func TestFindingType_Uniqueness(t *testing.T) {
	types := []FindingType{
		FindingVulnerability,
		FindingLicense,
		FindingProvenance,
		FindingReputation,
		FindingMalware,
	}

	seen := make(map[FindingType]bool)
	for _, ft := range types {
		require.False(t, seen[ft], "duplicate FindingType: %s", ft)
		seen[ft] = true
	}
	assert.Len(t, seen, 5)
}

func TestVerdict_HighestAction(t *testing.T) {
	tests := []struct {
		name string
		v    Verdict
		want VerdictAction
	}{
		{
			name: "no packages returns own action",
			v:    Verdict{Action: VerdictAllow},
			want: VerdictAllow,
		},
		{
			name: "block overrides allow",
			v: Verdict{
				Action: VerdictAllow,
				Packages: map[string]PackageVerdict{
					"foo": {Action: VerdictBlock},
				},
			},
			want: VerdictBlock,
		},
		{
			name: "approve overrides warn",
			v: Verdict{
				Action: VerdictWarn,
				Packages: map[string]PackageVerdict{
					"foo": {Action: VerdictAllow},
					"bar": {Action: VerdictApprove},
				},
			},
			want: VerdictApprove,
		},
		{
			name: "highest among multiple packages",
			v: Verdict{
				Action: VerdictAllow,
				Packages: map[string]PackageVerdict{
					"a": {Action: VerdictAllow},
					"b": {Action: VerdictWarn},
					"c": {Action: VerdictBlock},
				},
			},
			want: VerdictBlock,
		},
		{
			name: "all allow",
			v: Verdict{
				Action: VerdictAllow,
				Packages: map[string]PackageVerdict{
					"a": {Action: VerdictAllow},
					"b": {Action: VerdictAllow},
				},
			},
			want: VerdictAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.v.HighestAction())
		})
	}
}

func TestVerdictAction_Weight_Ordering(t *testing.T) {
	assert.Less(t, VerdictAllow.weight(), VerdictWarn.weight())
	assert.Less(t, VerdictWarn.weight(), VerdictApprove.weight())
	assert.Less(t, VerdictApprove.weight(), VerdictBlock.weight())
}

func TestInstallPlan_AllPackages(t *testing.T) {
	plan := InstallPlan{
		Direct: []PackageRef{
			{Name: "express", Version: "4.18.0", Direct: true},
		},
		Transitive: []PackageRef{
			{Name: "accepts", Version: "1.3.8"},
			{Name: "mime-types", Version: "2.1.35"},
		},
	}

	all := plan.AllPackages()
	assert.Len(t, all, 3)
	assert.Equal(t, "express", all[0].Name)
	assert.Equal(t, "accepts", all[1].Name)
	assert.Equal(t, "mime-types", all[2].Name)
}

func TestInstallPlan_AllPackages_Empty(t *testing.T) {
	plan := InstallPlan{}
	all := plan.AllPackages()
	assert.Empty(t, all)
}

func TestInstallPlan_AllPackagesWithRegistry(t *testing.T) {
	plan := InstallPlan{
		Registry: "registry.npmjs.org",
		Direct:   []PackageRef{{Name: "lodash", Version: "1"}, {Name: "weird", Version: "1", Registry: "explicit.example"}},
		Transitive: []PackageRef{{Name: "underscore", Version: "1"}},
	}
	out := plan.AllPackagesWithRegistry()
	if len(out) != 3 {
		t.Fatalf("want 3 packages, got %d", len(out))
	}
	if out[0].Registry != "registry.npmjs.org" {
		t.Errorf("direct[0] should inherit plan registry, got %q", out[0].Registry)
	}
	if out[1].Registry != "explicit.example" {
		t.Errorf("explicit registry must be preserved, got %q", out[1].Registry)
	}
	if out[2].Registry != "registry.npmjs.org" {
		t.Errorf("transitive[0] should inherit plan registry, got %q", out[2].Registry)
	}
}

func TestInstallPlan_AllPackagesWithRegistry_EmptyPlanRegistry(t *testing.T) {
	plan := InstallPlan{
		Direct: []PackageRef{{Name: "lodash", Version: "1"}},
	}
	out := plan.AllPackagesWithRegistry()
	if len(out) != 1 {
		t.Fatalf("want 1 package, got %d", len(out))
	}
	if out[0].Registry != "" {
		t.Errorf("empty plan.Registry must NOT make up a value; got %q", out[0].Registry)
	}
}

func TestSkippedPackage_ReasonString(t *testing.T) {
	tests := []struct {
		name   string
		reason SkipReason
		want   string
	}{
		{
			name:   "private registry",
			reason: SkipReasonPrivateRegistry,
			want:   "private_registry",
		},
		{
			name:   "private scope denylist",
			reason: SkipReasonPrivateScopeDenylist,
			want:   "private_scope_denylist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SkippedPackage{
				Package: PackageRef{Name: "@acme/internal", Version: "1.0.0"},
				Reason:  tt.reason,
			}
			assert.Equal(t, tt.want, string(s.Reason))
		})
	}
}

func TestVerdict_SkippedSurfaced(t *testing.T) {
	v := Verdict{
		Action: VerdictAllow,
		Skipped: []SkippedPackage{{
			Package: PackageRef{Name: "@acme/internal", Version: "1.0.0"},
			Reason:  SkipReasonPrivateRegistry,
		}},
	}
	assert.Len(t, v.Skipped, 1)
	assert.Equal(t, SkipReasonPrivateRegistry, v.Skipped[0].Reason)
}

func TestInstallPlan_AllPackagesWithRegistry_ScopedPackagePreservesEmpty(t *testing.T) {
	plan := InstallPlan{
		Registry: "registry.npmjs.org",
		Direct: []PackageRef{
			{Name: "lodash", Version: "1"},                  // unscoped → inherits
			{Name: "@acme/private", Version: "1"},           // scoped, empty Registry → kept empty
			{Name: "@acme/public", Version: "1", Registry: "registry.npmjs.org"}, // scoped with explicit → kept
		},
	}
	out := plan.AllPackagesWithRegistry()
	if out[0].Registry != "registry.npmjs.org" {
		t.Errorf("unscoped should inherit; got %q", out[0].Registry)
	}
	if out[1].Registry != "" {
		t.Errorf("scoped with empty must NOT inherit (privacy fail-closed); got %q", out[1].Registry)
	}
	if out[2].Registry != "registry.npmjs.org" {
		t.Errorf("scoped with explicit must be preserved; got %q", out[2].Registry)
	}
}

func TestIsScopedName(t *testing.T) {
	cases := map[string]bool{
		"@acme/foo":      true,
		"@scope/pkg":     true,
		"@":              false,
		"@noslash":       false,
		"plain":          false,
		"":               false,
	}
	for name, want := range cases {
		if got := isScopedName(name); got != want {
			t.Errorf("isScopedName(%q)=%v, want %v", name, got, want)
		}
	}
}
