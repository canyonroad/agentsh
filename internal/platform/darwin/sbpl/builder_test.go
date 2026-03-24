package sbpl

import (
	"strings"
	"testing"
)

func TestNew_ProducesValidEmptyProfile(t *testing.T) {
	p := New()
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !strings.HasPrefix(out, "(version 1)") {
		t.Errorf("Build() output should start with (version 1), got:\n%s", out)
	}
	if !strings.Contains(out, "(deny default)") {
		t.Error("Build() output should contain (deny default)")
	}
}

func TestAllowFileRead_Subpath(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, "/usr/lib")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow file-read* (subpath "/usr/lib"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestAllowFileRead_Literal(t *testing.T) {
	p := New()
	p.AllowFileRead(Literal, "/etc/hosts")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow file-read* (literal "/etc/hosts"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestAllowFileReadWrite_Subpath(t *testing.T) {
	p := New()
	p.AllowFileReadWrite(Subpath, "/workspace/project")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow file-read* file-write* (subpath "/workspace/project"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestBuild_RejectsRelativePath(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, "relative/path")
	_, err := p.Build()
	if err == nil {
		t.Error("Build() should return error for relative path")
	}
}

func TestBuild_EscapesQuotesInPaths(t *testing.T) {
	p := New()
	p.AllowFileRead(Literal, `/path/with"quotes`)
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow file-read* (literal "/path/with\"quotes"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestAllowFileReadWriteIOctl_Subpath(t *testing.T) {
	p := New()
	p.AllowFileReadWriteIOctl(Subpath, "/dev/tty")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow file-read* file-write* file-ioctl (subpath "/dev/tty"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestAllowFileRead_Regex(t *testing.T) {
	p := New()
	p.AllowFileRead(Regex, `#"/usr/lib/.*\.dylib"#`)
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow file-read* (regex #"/usr/lib/.*\.dylib"#))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestBuild_RegexPathNotRejected(t *testing.T) {
	p := New()
	// Regex paths don't need to be absolute
	p.AllowFileRead(Regex, `#"relative/.*"#`)
	_, err := p.Build()
	if err != nil {
		t.Errorf("Build() should not reject regex paths, got error: %v", err)
	}
}

func TestQuotePathForMatch(t *testing.T) {
	tests := []struct {
		name     string
		match    PathMatch
		input    string
		expected string
	}{
		{"simple path", Subpath, "/usr/lib", `"/usr/lib"`},
		{"path with quotes", Literal, `/path"quoted`, `"/path\"quoted"`},
		{"path with backslash", Literal, `/path\slash`, `"/path\\slash"`},
		{"regex passthrough", Regex, `#"/pattern"#`, `#"/pattern"#`},
		{"hash prefix NOT treated as regex when match is Literal", Literal, `#"not-regex`, `"#\"not-regex"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quotePathForMatch(tt.match, tt.input)
			if got != tt.expected {
				t.Errorf("quotePathForMatch(%v, %q) = %q, want %q", tt.match, tt.input, got, tt.expected)
			}
		})
	}
}

func TestBuild_DenyBeforeAllow(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, "/usr/lib")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	denyIdx := strings.Index(out, "(deny default)")
	allowIdx := strings.Index(out, "(allow file-read*")
	if denyIdx > allowIdx {
		t.Error("deny rules should appear before allow rules")
	}
}

func TestBuild_MultipleRules(t *testing.T) {
	p := New()
	p.AllowFileRead(Subpath, "/usr/lib")
	p.AllowFileReadWrite(Subpath, "/workspace")
	p.AllowFileRead(Literal, "/etc/hosts")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !strings.Contains(out, `(allow file-read* (subpath "/usr/lib"))`) {
		t.Error("missing file-read subpath rule")
	}
	if !strings.Contains(out, `(allow file-read* file-write* (subpath "/workspace"))`) {
		t.Error("missing file-read-write subpath rule")
	}
	if !strings.Contains(out, `(allow file-read* (literal "/etc/hosts"))`) {
		t.Error("missing file-read literal rule")
	}
}

// --- Process exec tests ---

func TestAllowProcessExec_Subpath(t *testing.T) {
	p := New()
	p.AllowProcessExec(Subpath, "/usr/bin")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow process-exec (subpath "/usr/bin"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestDenyProcessExec_Literal(t *testing.T) {
	p := New()
	p.DenyProcessExec(Literal, "/usr/bin/osascript")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(deny process-exec (literal "/usr/bin/osascript"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestDenyBeforeAllow_ExecOrdering(t *testing.T) {
	p := New()
	p.AllowProcessExec(Subpath, "/usr/bin")
	p.DenyProcessExec(Literal, "/usr/bin/osascript")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	denyIdx := strings.Index(out, `(deny process-exec`)
	allowIdx := strings.Index(out, `(allow process-exec`)
	if denyIdx < 0 {
		t.Fatal("deny process-exec rule not found in output")
	}
	if allowIdx < 0 {
		t.Fatal("allow process-exec rule not found in output")
	}
	if denyIdx > allowIdx {
		t.Errorf("deny exec rules should appear before allow exec rules, deny at %d, allow at %d", denyIdx, allowIdx)
	}
}

// --- Mach-lookup tests ---

func TestAllowMachLookup(t *testing.T) {
	p := New()
	p.AllowMachLookup("com.apple.system.logger")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow mach-lookup (global-name "com.apple.system.logger"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestAllowMachLookupPrefix(t *testing.T) {
	p := New()
	p.AllowMachLookupPrefix("com.apple.system.")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow mach-lookup (global-name-prefix "com.apple.system."))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestDenyMachLookup(t *testing.T) {
	p := New()
	p.DenyMachLookup("com.apple.security.authtrampoline")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(deny mach-lookup (global-name "com.apple.security.authtrampoline"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestDenyMachLookupPrefix(t *testing.T) {
	p := New()
	p.DenyMachLookupPrefix("com.apple.pasteboard.")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(deny mach-lookup (global-name-prefix "com.apple.pasteboard."))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

// --- Network tests ---

func TestAllowNetworkAll(t *testing.T) {
	p := New()
	p.AllowNetworkAll()
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow network*)`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

func TestAllowNetworkOutbound(t *testing.T) {
	p := New()
	p.AllowNetworkOutbound("tcp", "*:443")
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	expected := `(allow network-outbound (remote "tcp" "*:443"))`
	if !strings.Contains(out, expected) {
		t.Errorf("Build() output should contain %q, got:\n%s", expected, out)
	}
}

// --- AllowSystemEssentials tests ---

func TestAllowSystemEssentials_ContainsRequiredPaths(t *testing.T) {
	p := New()
	p.AllowSystemEssentials()
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	required := []string{
		// Dev files
		`(literal "/dev/null")`,
		`(literal "/dev/random")`,
		`(literal "/dev/urandom")`,
		`(literal "/dev/zero")`,
		// System libs
		`(subpath "/usr/lib")`,
		`(subpath "/usr/share")`,
		`(subpath "/System/Library")`,
		`(subpath "/Library/Frameworks")`,
		`(subpath "/private/var/db/dyld")`,
		// Process ops
		`(allow process-fork)`,
		`(allow signal (target self))`,
		`(allow sysctl-read)`,
		// TTY
		`(literal "/dev/tty")`,
		// Tool paths
		`(subpath "/usr/bin")`,
		`(subpath "/usr/sbin")`,
		`(subpath "/bin")`,
		`(subpath "/sbin")`,
		`(subpath "/usr/local/bin")`,
		`(subpath "/opt/homebrew/bin")`,
		`(subpath "/opt/homebrew/Cellar")`,
		// Temp
		`(subpath "/tmp")`,
		`(subpath "/private/tmp")`,
		`(subpath "/var/folders")`,
		// IPC
		`(allow ipc-posix*)`,
		`(allow mach-register)`,
	}

	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("AllowSystemEssentials output missing %q", s)
		}
	}
}

func TestAllowSystemEssentials_ContainsTTYRegex(t *testing.T) {
	p := New()
	p.AllowSystemEssentials()
	out, err := p.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	ttyPatterns := []string{
		`^/dev/ttys[0-9]+$`,
		`^/dev/pty[pqrs][0-9a-f]$`,
	}

	for _, pat := range ttyPatterns {
		if !strings.Contains(out, pat) {
			t.Errorf("AllowSystemEssentials output missing TTY regex %q", pat)
		}
	}
}
