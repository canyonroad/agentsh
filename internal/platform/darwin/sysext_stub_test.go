//go:build !darwin

package darwin

import (
	"testing"
)

func TestNewSysExtManager_Stub(t *testing.T) {
	m := NewSysExtManager()
	if m == nil {
		t.Fatal("NewSysExtManager() returned nil")
	}
}

func TestSysExtManager_Status_Stub(t *testing.T) {
	m := NewSysExtManager()

	status, err := m.Status()
	if err != nil {
		t.Fatalf("Status() error = %v, want nil", err)
	}
	if status == nil {
		t.Fatal("Status() returned nil status")
	}
	if status.Error == "" {
		t.Error("Expected status.Error to indicate macOS-only")
	}
}

func TestSysExtManager_Install_Stub(t *testing.T) {
	m := NewSysExtManager()

	err := m.Install()
	if err == nil {
		t.Fatal("Install() should return error on non-darwin")
	}
}

func TestSysExtManager_Uninstall_Stub(t *testing.T) {
	m := NewSysExtManager()

	err := m.Uninstall()
	if err == nil {
		t.Fatal("Uninstall() should return error on non-darwin")
	}
}
