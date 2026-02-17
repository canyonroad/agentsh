//go:build otel_integration

package otel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestIntegration_OTELCollector(t *testing.T) {
	// Check if docker is available.
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH, skipping integration test")
	}

	containerName := fmt.Sprintf("otel-test-%d", time.Now().UnixNano())

	// Create a temp directory for the collector output.
	// We mount it as a volume so the collector (running as non-root) can write to it.
	tmpDir := t.TempDir()
	os.Chmod(tmpDir, 0777)

	// Resolve absolute path to the collector config.
	configPath, err := filepath.Abs("testdata/otel-collector-config.yaml")
	if err != nil {
		t.Fatalf("resolving config path: %v", err)
	}

	// Start the OTEL Collector container.
	//nolint:gosec // Test code, arguments are not user-supplied.
	startCmd := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", "4317:4317",
		"-p", "4318:4318",
		"-v", configPath+":/etc/otelcol-contrib/config.yaml:ro",
		"-v", tmpDir+":/tmp/otelout",
		"otel/opentelemetry-collector-contrib:latest",
		"--config=/etc/otelcol-contrib/config.yaml",
	)
	startOut, err := startCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("starting collector container: %v\noutput: %s", err, startOut)
	}

	// Ensure cleanup.
	t.Cleanup(func() {
		// Dump logs on failure for debugging.
		if t.Failed() {
			//nolint:gosec
			out, _ := exec.Command("docker", "logs", containerName).CombinedOutput()
			t.Logf("collector logs:\n%s", string(out))
		}
		//nolint:gosec // Test cleanup.
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	})

	// Wait for the collector to be ready.
	if !waitForCollector(t, containerName, 30*time.Second) {
		t.Fatal("collector did not become ready in time")
	}

	// Create the OTEL store pointing at the local collector.
	ctx := context.Background()
	res := BuildResource("agentsh-integration-test", nil)

	store, err := New(ctx, Config{
		Endpoint:   "localhost:4317",
		Protocol:   "grpc",
		TLSEnabled: false,
		Signals: struct {
			Logs bool
		}{
			Logs: true,
		},
		Resource: res,
	})
	if err != nil {
		t.Fatalf("creating otel store: %v", err)
	}

	// Send 5 test events.
	for i := 0; i < 5; i++ {
		ev := types.Event{
			Timestamp: time.Now(),
			Type:      "file_write",
			SessionID: fmt.Sprintf("integration-sess-%d", i),
			Path:      fmt.Sprintf("/workspace/test-%d.go", i),
		}
		if err := store.AppendEvent(ctx, ev); err != nil {
			t.Fatalf("AppendEvent[%d]: %v", i, err)
		}
	}

	// Close to flush pending records.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Wait for the collector to write output, then copy it out.
	outputFile := filepath.Join(tmpDir, "otel-output.json")
	var content []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		content, _ = os.ReadFile(outputFile)
		if len(content) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Assert: file is non-empty.
	if len(content) == 0 {
		t.Fatal("output file is empty after waiting; collector did not write any data")
	}

	output := string(content)

	// Assert: contains service name.
	if !strings.Contains(output, "agentsh-integration-test") {
		t.Errorf("output does not contain service name 'agentsh-integration-test':\n%s", truncate(output, 2000))
	}

	// Assert: contains event type.
	if !strings.Contains(output, "file_write") {
		t.Errorf("output does not contain event type 'file_write':\n%s", truncate(output, 2000))
	}

	t.Logf("integration test passed, output size: %d bytes", len(content))
}

// waitForCollector polls the container logs until the collector reports ready
// or the timeout expires.
func waitForCollector(t *testing.T, containerName string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		//nolint:gosec // Test code.
		out, err := exec.Command("docker", "logs", containerName).CombinedOutput()
		if err == nil && strings.Contains(string(out), "Everything is ready") {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

// truncate returns the first n bytes of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
