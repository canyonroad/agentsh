package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseTemplate = `
version: 1
name: coding-agent
file_rules:
  - name: allow-tmp
    paths: ["/tmp/**"]
    operations: ["*"]
    decision: allow
`

func TestMergeAndWritePolicy_NoOverlay(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, overlay, out); err != nil {
		t.Fatalf("mergeAndWritePolicy: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "allow-tmp") {
		t.Errorf("expected output to contain base rules; got: %s", got)
	}
}

func TestMergeAndWritePolicy_WithOverlay(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	overlayBody := `
version: 1
name: user-overlay
file_rules:
  - name: allow-extra
    paths: ["/data/**"]
    operations: ["*"]
    decision: allow
`
	if err := os.WriteFile(overlay, []byte(overlayBody), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, overlay, out); err != nil {
		t.Fatalf("mergeAndWritePolicy: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "allow-tmp") {
		t.Error("expected base rule allow-tmp in merged output")
	}
	if !strings.Contains(body, "allow-extra") {
		t.Error("expected overlay rule allow-extra in merged output")
	}
}

func TestMergeAndWritePolicy_BadOverlayFallsBackToTemplate(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, []byte("not: [valid: yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, overlay, out); err != nil {
		t.Fatalf("mergeAndWritePolicy should not error on bad overlay: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "allow-tmp") {
		t.Error("expected fallback to template-only on bad overlay")
	}
}

func TestMergeAndWritePolicy_MissingTemplateErrors(t *testing.T) {
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "nonexistent.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	out := filepath.Join(dir, "out.yaml")

	err := mergeAndWritePolicy(tmpl, overlay, out)
	if err == nil {
		t.Fatal("expected error when template is missing")
	}
}

func TestMergeAndWritePolicy_AtomicWrite(t *testing.T) {
	// If the destination already exists with content X, and the merge succeeds,
	// the file should contain the new content (i.e. rename, not append).
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "tmpl.yaml")
	out := filepath.Join(dir, "out.yaml")

	if err := os.WriteFile(tmpl, []byte(baseTemplate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("stale: content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := mergeAndWritePolicy(tmpl, "", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "stale") {
		t.Error("expected stale content to be replaced")
	}
}
