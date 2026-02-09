package windows

import (
	"strings"
	"testing"
)

func TestRedirectConfig_Fields(t *testing.T) {
	cfg := RedirectConfig{
		StubBinary: `C:\agentsh\agentsh-stub.exe`,
		SessionID:  "test-session-123",
	}
	if cfg.StubBinary != `C:\agentsh\agentsh-stub.exe` {
		t.Errorf("unexpected StubBinary: %s", cfg.StubBinary)
	}
	if cfg.SessionID != "test-session-123" {
		t.Errorf("unexpected SessionID: %s", cfg.SessionID)
	}
}

func TestGenerateStubPipeNameForRedirect(t *testing.T) {
	name := generateStubPipeNameForRedirect("sess-abc", 1234)
	if !strings.HasPrefix(name, `\\.\pipe\agentsh-stub-sess-abc-1234-`) {
		t.Errorf("unexpected pipe name: %s", name)
	}
	// Verify uniqueness (nanos suffix differs)
	name2 := generateStubPipeNameForRedirect("sess-abc", 1234)
	if name == name2 {
		t.Errorf("pipe names should be unique, got same: %s", name)
	}
}

func TestSplitCommandLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple",
			input:    `cmd.exe /c dir`,
			expected: []string{"cmd.exe", "/c", "dir"},
		},
		{
			name:     "quoted path",
			input:    `"C:\Program Files\git\bin\git.exe" push origin main`,
			expected: []string{`C:\Program Files\git\bin\git.exe`, "push", "origin", "main"},
		},
		{
			name:     "empty",
			input:    "",
			expected: nil,
		},
		{
			name:     "single command",
			input:    "notepad.exe",
			expected: []string{"notepad.exe"},
		},
		{
			name:     "quoted with spaces",
			input:    `"C:\My App\app.exe" "arg with spaces" --flag`,
			expected: []string{`C:\My App\app.exe`, "arg with spaces", "--flag"},
		},
		{
			name:     "tabs and extra spaces",
			input:    "cmd.exe  /c   dir",
			expected: []string{"cmd.exe", "/c", "dir"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitCommandLine(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("len mismatch: got %d (%v), want %d (%v)", len(result), result, len(tt.expected), tt.expected)
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("[%d] got %q, want %q", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestHandleRedirectSignature(t *testing.T) {
	// Verify handleRedirect exists with the expected signature
	var fn func(req *SuspendedProcessRequest, cfg RedirectConfig, onStubSpawned func(pid uint32)) error
	fn = handleRedirect
	if fn == nil {
		t.Fatal("handleRedirect should not be nil")
	}
}
