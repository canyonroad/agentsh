package policy

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationUnmarshal(t *testing.T) {
	var d duration
	if err := d.UnmarshalYAML(scalarNode("2s")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Duration != 2*time.Second {
		t.Fatalf("expected 2s, got %v", d.Duration)
	}
	if err := d.UnmarshalYAML(scalarNode("notadur")); err == nil {
		t.Fatalf("expected parse error")
	}
}

// scalarNode quickly builds a YAML scalar node for tests.
func scalarNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: v}
}
