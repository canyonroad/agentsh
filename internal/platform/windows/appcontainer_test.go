//go:build windows

package windows

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
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

func TestAppContainerCreateDelete(t *testing.T) {
	if !isAdmin() {
		t.Skip("requires admin privileges")
	}

	ac := newAppContainer("test-create-delete")

	// Create should succeed
	if err := ac.create(); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	defer ac.cleanup()

	if !ac.created {
		t.Error("created flag should be true")
	}
	if ac.sid == nil {
		t.Error("SID should be set after create")
	}

	// Cleanup should succeed
	if err := ac.cleanup(); err != nil {
		t.Errorf("cleanup failed: %v", err)
	}
}

func isAdmin() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}
