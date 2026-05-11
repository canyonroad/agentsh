package policy

import (
	"testing"
)

func TestMergeOverlay_OverlayWinsOnNameCollision(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "base",
		FileRules: []FileRule{
			{Name: "rule-a", Decision: "allow", Paths: []string{"/a"}},
			{Name: "rule-b", Decision: "allow", Paths: []string{"/b"}},
		},
	}
	overlay := &Policy{
		Version: 1,
		Name:    "overlay",
		FileRules: []FileRule{
			{Name: "rule-b", Decision: "deny", Paths: []string{"/b"}},
			{Name: "rule-c", Decision: "allow", Paths: []string{"/c"}},
		},
	}

	merged := MergeOverlay(base, overlay)

	if got := len(merged.FileRules); got != 3 {
		t.Fatalf("len(FileRules) = %d, want 3", got)
	}
	if merged.FileRules[0].Name != "rule-a" {
		t.Errorf("FileRules[0].Name = %q, want rule-a", merged.FileRules[0].Name)
	}
	if merged.FileRules[1].Name != "rule-b" || merged.FileRules[1].Decision != "deny" {
		t.Errorf("FileRules[1] = %+v, want rule-b with decision=deny (overlay wins)", merged.FileRules[1])
	}
	if merged.FileRules[2].Name != "rule-c" {
		t.Errorf("FileRules[2].Name = %q, want rule-c", merged.FileRules[2].Name)
	}
}

func TestMergeOverlay_NilOverlayReturnsBase(t *testing.T) {
	base := &Policy{Version: 1, Name: "base", FileRules: []FileRule{{Name: "x"}}}
	merged := MergeOverlay(base, nil)
	if merged != base {
		t.Errorf("MergeOverlay(base, nil) should return base unchanged")
	}
}

func TestMergeOverlay_NilBaseReturnsOverlay(t *testing.T) {
	overlay := &Policy{Version: 1, Name: "overlay", FileRules: []FileRule{{Name: "x"}}}
	merged := MergeOverlay(nil, overlay)
	if merged != overlay {
		t.Errorf("MergeOverlay(nil, overlay) should return overlay unchanged")
	}
}

func TestMergeOverlay_PreservesAllRuleKinds(t *testing.T) {
	base := &Policy{
		Version:      1,
		Name:         "base",
		FileRules:    []FileRule{{Name: "f1"}},
		CommandRules: []CommandRule{{Name: "c1"}},
		SignalRules:  []SignalRule{{Name: "s1"}},
		NetworkRules: []NetworkRule{{Name: "n1"}},
	}
	overlay := &Policy{
		Version:      1,
		Name:         "overlay",
		FileRules:    []FileRule{{Name: "f2"}},
		CommandRules: []CommandRule{{Name: "c2"}},
		SignalRules:  []SignalRule{{Name: "s2"}},
		NetworkRules: []NetworkRule{{Name: "n2"}},
	}
	merged := MergeOverlay(base, overlay)
	if len(merged.FileRules) != 2 || len(merged.CommandRules) != 2 ||
		len(merged.SignalRules) != 2 || len(merged.NetworkRules) != 2 {
		t.Errorf("merged rule counts wrong: %+v", merged)
	}
}

func TestMergeOverlay_KeepsBaseMetadata(t *testing.T) {
	base := &Policy{Version: 1, Name: "base", Description: "from base"}
	overlay := &Policy{Version: 1, Name: "overlay"}
	merged := MergeOverlay(base, overlay)
	if merged.Name != "base" {
		t.Errorf("merged.Name = %q, want %q (base metadata preserved)", merged.Name, "base")
	}
	if merged.Description != "from base" {
		t.Errorf("merged.Description = %q, want %q", merged.Description, "from base")
	}
}
