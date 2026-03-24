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

func TestQuotePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple path", "/usr/lib", `"/usr/lib"`},
		{"path with quotes", `/path"quoted`, `"/path\"quoted"`},
		{"path with backslash", `/path\slash`, `"/path\\slash"`},
		{"regex passthrough", `#"/pattern"#`, `#"/pattern"#`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := quotePath(tt.input)
			if got != tt.expected {
				t.Errorf("quotePath(%q) = %q, want %q", tt.input, got, tt.expected)
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
