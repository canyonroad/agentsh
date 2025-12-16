package cli

import "testing"

func TestRoot_WiresPolicyAndConfig(t *testing.T) {
	root := NewRoot("test")
	foundPolicy := false
	foundConfig := false
	for _, c := range root.Commands() {
		if c.Name() == "policy" {
			foundPolicy = true
		}
		if c.Name() == "config" {
			foundConfig = true
		}
	}
	if !foundPolicy {
		t.Fatalf("expected policy command to be registered")
	}
	if !foundConfig {
		t.Fatalf("expected config command to be registered")
	}
}
