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
//
// The tip Action is structured as "<recommendation sentence>. Note:
// <cautionary sentence>" so tests can assert that DropCapabilities only
// appears in the cautionary sentence (not as a standalone remediation)
// without needing a brittle exact-phrase match. The Note: marker MUST
// exist — a regression that drops the DropCapabilities warning entirely
// would silently pass if the marker were optional, so the test below
// asserts all three: the marker exists, the cautionary section is
// non-empty, and it mentions DropCapabilities.
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

	// The "Note:" marker must exist so the recommendation sentence
	// can be unambiguously separated from the cautionary DropCapabilities
	// explanation. A regression that removes the marker — for example,
	// by dropping the cautionary section entirely — must fail this test
	// rather than silently passing the remaining checks.
	noteIdx := strings.Index(tip.Action, "Note:")
	if noteIdx < 0 {
		t.Fatalf("capability-drop Action missing required 'Note:' marker separating recommendation from cautionary section: %q", tip.Action)
	}
	recommendation := strings.TrimSpace(tip.Action[:noteIdx])
	caution := strings.TrimSpace(tip.Action[noteIdx:])

	// The recommendation sentence must mention at least one concrete
	// mechanism that lowers the running process's permitted/effective
	// sets at startup.
	wantAny := []string{"CapabilityBoundingSet", "--cap-drop", "unprivileged user"}
	var matched bool
	for _, s := range wantAny {
		if strings.Contains(recommendation, s) {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("capability-drop Action recommendation sentence should reference a startup drop mechanism, got %q", recommendation)
	}

	// DropCapabilities must NOT appear in the recommendation sentence
	// under any wording ("call DropCapabilities", "use DropCapabilities",
	// or just "DropCapabilities" as a bullet). It may only appear in
	// the cautionary note explaining why it is not a substitute.
	if strings.Contains(recommendation, "DropCapabilities") {
		t.Errorf("capability-drop Action recommendation sentence must not mention DropCapabilities as a remediation: %q", recommendation)
	}
	// The cautionary note must be non-empty and explicitly explain
	// why DropCapabilities is insufficient — otherwise operators who
	// already know about it will keep trying to use it. These checks
	// are unconditional (not gated on caution != "") so that removing
	// the cautionary section fails the test instead of skipping it.
	if caution == "" {
		t.Errorf("capability-drop Action cautionary section after 'Note:' must be non-empty: %q", tip.Action)
	}
	if !strings.Contains(caution, "DropCapabilities") {
		t.Errorf("capability-drop cautionary note must explain why DropCapabilities is not a substitute, got %q", caution)
	}
}
