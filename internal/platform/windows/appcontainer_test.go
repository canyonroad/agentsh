//go:build windows

package windows

import (
	"strings"
	"testing"
)

func TestAppContainerName(t *testing.T) {
	name := appContainerName("test-sandbox-123")
	if !strings.HasPrefix(name, "agentsh-sandbox-") {
		t.Errorf("expected prefix 'agentsh-sandbox-', got %s", name)
	}
	if !strings.Contains(name, "test-sandbox-123") {
		t.Errorf("expected to contain sandbox id, got %s", name)
	}
}

func TestAppContainerNameSanitization(t *testing.T) {
	// Container names must be valid for registry keys
	name := appContainerName(`test/with\special:chars*?"<>|more`)
	if strings.ContainsAny(name, `/\:*?"<>|`) {
		t.Errorf("name should not contain special chars: %s", name)
	}
}
