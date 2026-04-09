//go:build linux || darwin || windows

package capabilities

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateTips_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	caps := map[string]any{
		"seccomp":          false,
		"landlock":         true,
		"landlock_abi":     3,
		"landlock_network": false,
		"fuse":             false,
		"ebpf":             false,
	}

	tips := GenerateTips("linux", caps)

	// Should have tips for missing features
	hasFuseTip := false
	hasNetworkTip := false
	for _, tip := range tips {
		if tip.Feature == "fuse" {
			hasFuseTip = true
			if tip.Action == "" {
				t.Error("fuse tip missing action")
			}
		}
		if tip.Feature == "landlock_network" {
			hasNetworkTip = true
		}
	}

	if !hasFuseTip {
		t.Error("missing fuse tip")
	}
	if !hasNetworkTip {
		t.Error("missing landlock_network tip")
	}
}

func TestGenerateTips_Darwin(t *testing.T) {
	caps := map[string]any{
		"sandbox_exec": true,
		"esf":          false,
	}

	tips := GenerateTips("darwin", caps)

	hasESFTip := false
	for _, tip := range tips {
		if tip.Feature == "esf" {
			hasESFTip = true
			if tip.Action == "" {
				t.Error("esf tip missing action")
			}
		}
		if tip.Feature == "fuse_t" {
			t.Error("unexpected fuse_t tip — FUSE-T support was removed")
		}
	}

	if !hasESFTip {
		t.Error("missing esf tip")
	}
}

func TestGenerateTips_Windows(t *testing.T) {
	caps := map[string]any{
		"app_container": true,
		"winfsp":        false,
		"minifilter":    false,
	}

	tips := GenerateTips("windows", caps)

	hasWinfspTip := false
	for _, tip := range tips {
		if tip.Feature == "winfsp" {
			hasWinfspTip = true
		}
	}

	if !hasWinfspTip {
		t.Error("missing winfsp tip")
	}
}

func TestGenerateTipsFromDomains_ZeroScoreOnly(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Score: 25, Backends: []DetectedBackend{
			{Name: "fuse", Available: true},
		}},
		{Name: "Network", Weight: 20, Score: 0, Backends: []DetectedBackend{
			{Name: "ebpf", Available: false},
		}},
	}
	tips := GenerateTipsFromDomains(domains)
	// Only Network (score 0) should generate tips, not File (score 25)
	assert.Len(t, tips, 1)
	assert.Equal(t, "ebpf", tips[0].Feature)
	assert.Contains(t, tips[0].Impact, "+20 pts")
}

func TestGenerateTipsFromDomains_NoTipsWhenAllScored(t *testing.T) {
	domains := []ProtectionDomain{
		{Name: "File Protection", Weight: 25, Score: 25, Backends: []DetectedBackend{{Available: true}}},
		{Name: "Network", Weight: 20, Score: 20, Backends: []DetectedBackend{{Available: true}}},
	}
	tips := GenerateTipsFromDomains(domains)
	assert.Empty(t, tips)
}

func TestLookupTip(t *testing.T) {
	tip := lookupTip("ebpf")
	assert.NotNil(t, tip)
	assert.Equal(t, "ebpf", tip.Feature)

	tip2 := lookupTip("nonexistent")
	assert.Nil(t, tip2)
}

// TestLookupTip_CapabilityDropSemanticsChanged guards against regressing the
// capability-drop tip to the pre-#198 text. The old tip said the backend
// was "unavailable" and told the user to "Run with standard Linux
// capabilities support" — both wrong under the new probe semantics, where
// the backend is reported inactive when the process retains full
// privileges. The correct remediation is to constrain the process's
// capabilities at startup via a mechanism that lowers both CapBnd AND
// CapPrm/CapEff. capabilities.DropCapabilities() is deliberately NOT
// recommended because it only narrows the bounding set via
// PR_CAPBSET_DROP; following that advice would leave the process able to
// use its existing permitted set while still tripping the probe.
func TestLookupTip_CapabilityDropSemanticsChanged(t *testing.T) {
	tip := lookupTip("capability-drop")
	if tip == nil {
		t.Fatal("capability-drop tip missing")
	}
	if strings.Contains(strings.ToLower(tip.Impact), "unavailable") {
		t.Errorf("capability-drop Impact still says 'unavailable': %q", tip.Impact)
	}
	if strings.Contains(tip.Action, "standard Linux capabilities support") {
		t.Errorf("capability-drop Action still references the old misleading text: %q", tip.Action)
	}
	// The new action must mention at least one concrete mechanism that
	// lowers the running process's permitted/effective sets at startup
	// so operators get actionable advice.
	wantAny := []string{"CapabilityBoundingSet", "--cap-drop", "unprivileged user"}
	var matched bool
	for _, s := range wantAny {
		if strings.Contains(tip.Action, s) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("capability-drop Action should reference a startup drop mechanism, got %q", tip.Action)
	}
	// capabilities.DropCapabilities() only narrows the bounding set, so
	// it must NOT appear as a standalone recommendation. It may be
	// mentioned as a cautionary note (explaining why it's insufficient)
	// but not as a remediation step.
	if strings.Contains(tip.Action, "call capabilities.DropCapabilities") {
		t.Errorf("capability-drop Action recommends DropCapabilities() which only narrows CapBnd: %q", tip.Action)
	}
}
