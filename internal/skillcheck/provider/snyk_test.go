package provider

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

func TestSnyk_BinaryPath_HappyPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake CLI is a sh script")
	}
	abs, err := filepath.Abs(filepath.Join("..", "testdata", "snyk-fake", "snyk-agent-scan-fake.sh"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	p := NewSnykProvider(SnykConfig{BinaryPath: abs})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := p.Scan(ctx, loadFixture(t, "minimal"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(resp.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(resp.Findings))
	}
	if resp.Findings[0].Type != skillcheck.FindingPromptInjection {
		t.Errorf("first finding type=%s", resp.Findings[0].Type)
	}
	if resp.Findings[1].Severity != skillcheck.SeverityCritical {
		t.Errorf("second finding severity=%s", resp.Findings[1].Severity)
	}
}

func TestSnyk_NoBinaryAvailable(t *testing.T) {
	p := NewSnykProvider(SnykConfig{
		BinaryPath:   "",
		PathLookup:   func(string) (string, error) { return "", &noBinaryErr{} },
		UvxAvailable: func() bool { return false },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	resp, err := p.Scan(ctx, loadFixture(t, "minimal"))
	if err != nil {
		t.Fatalf("Scan should not return error; OnFailure handles it: %v", err)
	}
	if !strings.Contains(resp.Metadata.Error, "no executable found") {
		t.Errorf("metadata.error=%q", resp.Metadata.Error)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("no findings expected, got %d", len(resp.Findings))
	}
}

type noBinaryErr struct{}

func (*noBinaryErr) Error() string { return "exec: not found" }
