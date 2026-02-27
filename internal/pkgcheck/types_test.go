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
