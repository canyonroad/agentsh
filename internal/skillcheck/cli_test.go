package skillcheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_ScanReportsVerdict(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: skill\n---\n"), 0o644)

	var out bytes.Buffer
	cli := &CLI{
		Stdout:    &out,
		Providers: map[string]ProviderEntry{},
	}
	code := cli.Run(context.Background(), []string{"scan", skillDir})
	if code != 0 {
		t.Errorf("exit code=%d want 0", code)
	}
	if !strings.Contains(out.String(), "action=allow") {
		t.Errorf("expected verdict in output, got: %s", out.String())
	}
}

func TestCLI_ScanExitsNonZeroOnBlock(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: skill\n---\n"), 0o644)

	cli := &CLI{
		Stdout: new(bytes.Buffer),
		Providers: map[string]ProviderEntry{
			"x": {Provider: stubProvider{name: "x", findings: []Finding{{Severity: SeverityCritical}}}},
		},
	}
	code := cli.Run(context.Background(), []string{"scan", skillDir})
	if code == 0 {
		t.Errorf("expected non-zero exit on block; got 0")
	}
	if code != 3 {
		t.Errorf("expected exit code 3 for block; got %d", code)
	}
}

func TestCLI_DoctorListsProviders(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		Stdout: &out,
		Providers: map[string]ProviderEntry{
			"local": {Provider: stubProvider{name: "local"}},
			"snyk":  {Provider: stubProvider{name: "snyk"}},
		},
	}
	code := cli.Run(context.Background(), []string{"doctor"})
	if code != 0 {
		t.Errorf("doctor exit=%d", code)
	}
	if !strings.Contains(out.String(), "local") || !strings.Contains(out.String(), "snyk") {
		t.Errorf("doctor missing providers: %s", out.String())
	}
}

func TestCLI_DoctorSortedOutput(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{
		Stdout: &out,
		Providers: map[string]ProviderEntry{
			"zzz":   {Provider: stubProvider{name: "zzz"}},
			"aaa":   {Provider: stubProvider{name: "aaa"}},
			"local": {Provider: stubProvider{name: "local"}},
		},
	}
	cli.Run(context.Background(), []string{"doctor"})
	output := out.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %s", len(lines), output)
	}
	// Verify sorted order
	if !strings.HasPrefix(lines[0], "aaa") {
		t.Errorf("first line should be aaa, got: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "local") {
		t.Errorf("second line should be local, got: %s", lines[1])
	}
	if !strings.HasPrefix(lines[2], "zzz") {
		t.Errorf("third line should be zzz, got: %s", lines[2])
	}
}

func TestCLI_ExitCodePinning(t *testing.T) {
	// Usage error: no subcommand
	cli := &CLI{Stdout: new(bytes.Buffer), Providers: map[string]ProviderEntry{}}
	if code := cli.Run(context.Background(), []string{}); code != 2 {
		t.Errorf("empty argv: want exit 2, got %d", code)
	}
	// Usage error: unknown subcommand
	if code := cli.Run(context.Background(), []string{"bogus"}); code != 2 {
		t.Errorf("unknown cmd: want exit 2, got %d", code)
	}
	// scan missing path
	if code := cli.Run(context.Background(), []string{"scan"}); code != 2 {
		t.Errorf("scan no path: want exit 2, got %d", code)
	}
}

func TestCLI_PlaceholderSubcommands(t *testing.T) {
	for _, sub := range []string{"list-quarantined", "restore", "cache"} {
		var out bytes.Buffer
		cli := &CLI{Stdout: &out, Providers: map[string]ProviderEntry{}}
		code := cli.Run(context.Background(), []string{sub})
		if code != 0 {
			t.Errorf("%s: want exit 0, got %d", sub, code)
		}
		if !strings.Contains(out.String(), "not implemented yet") {
			t.Errorf("%s: want 'not implemented yet' in output, got: %s", sub, out.String())
		}
	}
}

func TestCLI_ProviderDenyFailureExitsBlock(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: skill\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cli := &CLI{
		Stdout: new(bytes.Buffer),
		Providers: map[string]ProviderEntry{
			"broken": {
				Provider:  stubProvider{name: "broken", err: errors.New("boom")},
				OnFailure: "deny",
			},
		},
	}
	code := cli.Run(context.Background(), []string{"scan", skillDir})
	if code != 3 {
		t.Errorf("expected exit code 3 (block) when provider with on_failure=deny fails; got %d", code)
	}
}

func TestCLI_PartialLimitsConfigStillScans(t *testing.T) {
	dir := t.TempDir()
	skillDir := filepath.Join(dir, "skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: skill\n---\nbody\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Configure ONLY PerFileBytes; TotalBytes left at 0 (would mean "no
	// skill exceeds 0 bytes" without defaulting → all loads fail).
	cli := &CLI{
		Stdout:    new(bytes.Buffer),
		Limits:    LoaderLimits{PerFileBytes: 16 * 1024},
		Providers: map[string]ProviderEntry{},
	}
	code := cli.Run(context.Background(), []string{"scan", skillDir})
	if code != 0 {
		t.Errorf("expected exit code 0 with partial limits; got %d (TotalBytes default not applied)", code)
	}
}
