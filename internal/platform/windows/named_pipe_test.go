package windows

import (
	"runtime"
	"strings"
	"testing"
)

func TestGenerateWrapPipeName(t *testing.T) {
	name := GenerateWrapPipeName("test-session-123")
	expected := `\\.\pipe\agentsh-wrap-test-session-123`
	if name != expected {
		t.Errorf("expected %q, got %q", expected, name)
	}
}

func TestGenerateStubPipeName(t *testing.T) {
	name := GenerateStubPipeName("sess-42", 1234)
	expected := `\\.\pipe\agentsh-stub-sess-42-1234`
	if name != expected {
		t.Errorf("expected %q, got %q", expected, name)
	}
}

func TestPipeSecuritySDDL(t *testing.T) {
	sddl := PipeSecuritySDDL()
	// Must contain SY (System), BA (Administrators), CO (Creator Owner)
	if !strings.Contains(sddl, "SY") {
		t.Error("SDDL should contain SY (Local System)")
	}
	if !strings.Contains(sddl, "BA") {
		t.Error("SDDL should contain BA (Built-in Administrators)")
	}
	if !strings.Contains(sddl, "CO") {
		t.Error("SDDL should contain CO (Creator Owner)")
	}
}

func TestListenNamedPipeStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping stub test on Windows")
	}
	_, err := ListenNamedPipe(`\\.\pipe\test`)
	if err == nil {
		t.Error("expected error on non-Windows")
	}
}

func TestDialNamedPipeStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping stub test on Windows")
	}
	_, err := DialNamedPipe(`\\.\pipe\test`, 0)
	if err == nil {
		t.Error("expected error on non-Windows")
	}
}
