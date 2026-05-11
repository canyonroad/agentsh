// Package sbxkit hosts a structural test for spec.yaml so a fresh engineer
// can't break the manifest format without CI catching it.
package sbxkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type kitSpec struct {
	SchemaVersion string   `yaml:"schemaVersion"`
	Kind          string   `yaml:"kind"`
	Name          string   `yaml:"name"`
	DisplayName   string   `yaml:"displayName"`
	Description   string   `yaml:"description"`
	Commands      kitCmds  `yaml:"commands"`
}

type kitCmds struct {
	Install   []kitInstall   `yaml:"install"`
	InitFiles []kitInitFile  `yaml:"initFiles"`
	Startup   []kitStartup   `yaml:"startup"`
}

type kitInstall struct {
	Command     string `yaml:"command"`
	User        string `yaml:"user"`
	Description string `yaml:"description"`
}

type kitInitFile struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
	Mode    string `yaml:"mode"`
}

type kitStartup struct {
	Command     []string `yaml:"command"`
	User        string   `yaml:"user"`
	Background  bool     `yaml:"background"`
	Description string   `yaml:"description"`
}

func loadSpec(t *testing.T) *kitSpec {
	t.Helper()
	path := filepath.Join("spec.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spec.yaml: %v", err)
	}
	var s kitSpec
	if err := yaml.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse spec.yaml: %v", err)
	}
	return &s
}

func TestSpecYAML_TopLevel(t *testing.T) {
	s := loadSpec(t)
	if s.SchemaVersion != "1" {
		t.Errorf("schemaVersion = %q, want %q", s.SchemaVersion, "1")
	}
	if s.Kind != "mixin" {
		t.Errorf("kind = %q, want %q", s.Kind, "mixin")
	}
	if s.Name != "agentsh" {
		t.Errorf("name = %q, want %q", s.Name, "agentsh")
	}
}

func TestSpecYAML_InstallReferencesInstallScript(t *testing.T) {
	s := loadSpec(t)
	if len(s.Commands.Install) != 1 {
		t.Fatalf("expected exactly one install command, got %d", len(s.Commands.Install))
	}
	cmd := s.Commands.Install[0].Command
	if !strings.Contains(cmd, "install.sh") {
		t.Errorf("install command does not curl install.sh: %q", cmd)
	}
	if s.Commands.Install[0].User != "0" {
		t.Errorf("install user = %q, want %q (root)", s.Commands.Install[0].User, "0")
	}
}

func TestSpecYAML_InitFilesSetShimPath(t *testing.T) {
	s := loadSpec(t)
	var foundProfile, foundEnv bool
	for _, f := range s.Commands.InitFiles {
		if f.Path == "/etc/profile.d/agentsh.sh" {
			foundProfile = true
			if !strings.Contains(f.Content, "/usr/lib/agentsh/shims") {
				t.Errorf("profile.d entry does not export shim PATH: %q", f.Content)
			}
		}
		if f.Path == "/etc/environment.d/10-agentsh.conf" {
			foundEnv = true
			if !strings.Contains(f.Content, "/usr/lib/agentsh/shims") {
				t.Errorf("environment.d entry does not include shim PATH: %q", f.Content)
			}
		}
	}
	if !foundProfile {
		t.Error("initFiles missing /etc/profile.d/agentsh.sh entry")
	}
	if !foundEnv {
		t.Error("initFiles missing /etc/environment.d/10-agentsh.conf entry")
	}
}

func TestSpecYAML_StartupInvokesBootstrap(t *testing.T) {
	s := loadSpec(t)
	if len(s.Commands.Startup) != 1 {
		t.Fatalf("expected exactly one startup command, got %d", len(s.Commands.Startup))
	}
	cmd := s.Commands.Startup[0]
	if len(cmd.Command) == 0 || cmd.Command[0] != "/usr/bin/agentsh-sbx-bootstrap" {
		t.Errorf("startup command = %v, want first element /usr/bin/agentsh-sbx-bootstrap", cmd.Command)
	}
	if !cmd.Background {
		t.Error("startup command must be background:true")
	}
}

func TestKitFiles_SkillExists(t *testing.T) {
	if _, err := os.Stat(filepath.Join("files", "workspace", ".claude", "skills", "agentsh", "SKILL.md")); err != nil {
		t.Errorf("SKILL.md missing: %v", err)
	}
}

func TestKitFiles_OverrideStubExists(t *testing.T) {
	if _, err := os.Stat(filepath.Join("files", "home", "agent", ".agentsh", "policy.yaml")); err != nil {
		t.Errorf("override stub missing: %v", err)
	}
}
