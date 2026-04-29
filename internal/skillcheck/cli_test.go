package skillcheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/trash"
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

func TestCLI_ListQuarantined_Empty(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"list-quarantined"})
	if code != 0 {
		t.Errorf("exit=%d want 0", code)
	}
	if !strings.Contains(out.String(), "no quarantined skills") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_ListQuarantined_NoTrashDir(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{Stdout: &out}
	code := cli.Run(context.Background(), []string{"list-quarantined"})
	if code != 1 {
		t.Errorf("exit=%d want 1", code)
	}
	if !strings.Contains(out.String(), "trash dir not configured") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_ListQuarantined_WithEntries(t *testing.T) {
	dir := t.TempDir()
	// Divert a real file so we have something to list.
	srcFile := filepath.Join(dir, "skill.md")
	if err := os.WriteFile(srcFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := trash.Divert(srcFile, trash.Config{TrashDir: dir, Command: "test-cmd"})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}

	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"list-quarantined"})
	if code != 0 {
		t.Errorf("exit=%d want 0", code)
	}
	if !strings.Contains(out.String(), srcFile) {
		t.Errorf("expected original path in output; got: %s", out.String())
	}
	if !strings.Contains(out.String(), "test-cmd") {
		t.Errorf("expected command in output; got: %s", out.String())
	}
}

func TestCLI_Restore_NoToken(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"restore"})
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
	if !strings.Contains(out.String(), "usage") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_Restore_NoTrashDir(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{Stdout: &out}
	code := cli.Run(context.Background(), []string{"restore", "sometoken"})
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
	if !strings.Contains(out.String(), "usage") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_Restore_RejectsExtraArgs(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"restore", "tok", "dest", "extra"})
	if code != 2 {
		t.Errorf("exit=%d want 2 (usage)", code)
	}
	if !strings.Contains(out.String(), "usage") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_Restore_BogusToken(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"restore", "bogus-token-xyz"})
	if code != 1 {
		t.Errorf("exit=%d want 1", code)
	}
	if !strings.Contains(out.String(), "restore:") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_Restore_HappyPath(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "skill.md")
	if err := os.WriteFile(srcFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry, err := trash.Divert(srcFile, trash.Config{TrashDir: dir, Command: "test-cmd"})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}

	// Restore to a new dest so we don't collide with original path.
	dest := filepath.Join(dir, "restored.md")
	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"restore", entry.Token, dest})
	if code != 0 {
		t.Errorf("exit=%d want 0; output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "restored to") {
		t.Errorf("got: %s", out.String())
	}
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("restored file does not exist: %v", err)
	}
}

func TestCLI_Restore_DestExists(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "skill.md")
	if err := os.WriteFile(srcFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry, err := trash.Divert(srcFile, trash.Config{TrashDir: dir, Command: "test-cmd"})
	if err != nil {
		t.Fatalf("divert: %v", err)
	}

	// Create a file at the dest before restore.
	dest := filepath.Join(dir, "existing.md")
	if err := os.WriteFile(dest, []byte("occupied"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cli := &CLI{Stdout: &out, TrashDir: dir}
	code := cli.Run(context.Background(), []string{"restore", entry.Token, dest})
	if code != 1 {
		t.Errorf("exit=%d want 1; output: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "restore:") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_Cache_DeferredPrune(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{Stdout: &out}
	code := cli.Run(context.Background(), []string{"cache", "prune"})
	if code != 0 {
		t.Errorf("exit=%d want 0", code)
	}
	if !strings.Contains(out.String(), "deferred") {
		t.Errorf("got: %s", out.String())
	}
}

func TestCLI_Cache_NoArgs(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{Stdout: &out}
	code := cli.Run(context.Background(), []string{"cache"})
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
	if !strings.Contains(out.String(), "usage") {
		t.Errorf("got: %s", out.String())
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
