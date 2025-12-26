package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewDiagnosticCollector(t *testing.T) {
	client := &mockClient{}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client: client,
		Output: buf,
	})

	if collector == nil {
		t.Fatal("expected non-nil collector")
	}
}

func TestDiagnosticCollector_Collect(t *testing.T) {
	client := &mockClient{
		status: &Status{
			Version:  "1.0.0",
			Healthy:  true,
			Platform: "linux",
		},
		metrics: &Metrics{
			SessionsTotal:  50,
			SessionsActive: 2,
		},
		config: map[string]any{
			"key": "value",
		},
		sessions: []SessionInfo{
			{ID: "sess-1", State: "running"},
		},
	}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client: client,
		Output: buf,
	})

	ctx := context.Background()
	report, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	if report.Status == nil {
		t.Error("report should have status")
	}
	if report.Metrics == nil {
		t.Error("report should have metrics")
	}
	if report.Config == nil {
		t.Error("report should have config")
	}
	if len(report.Sessions) != 1 {
		t.Errorf("report should have 1 session, got %d", len(report.Sessions))
	}
	if report.SystemInfo.OS == "" {
		t.Error("report should have system info")
	}
}

func TestDiagnosticCollector_RedactConfig(t *testing.T) {
	client := &mockClient{
		config: map[string]any{
			"database_password": "secret123",
			"api_key":           "key123",
			"auth_token":        "token123",
			"normal_value":      "visible",
			"nested": map[string]any{
				"secret_value": "hidden",
				"public_value": "shown",
			},
		},
	}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client:        client,
		Output:        buf,
		RedactSecrets: true,
	})

	ctx := context.Background()
	report, _ := collector.Collect(ctx)

	if report.Config["database_password"] != "[REDACTED]" {
		t.Error("password should be redacted")
	}
	if report.Config["api_key"] != "[REDACTED]" {
		t.Error("api_key should be redacted")
	}
	if report.Config["auth_token"] != "[REDACTED]" {
		t.Error("auth_token should be redacted")
	}
	if report.Config["normal_value"] != "visible" {
		t.Error("normal_value should not be redacted")
	}

	nested := report.Config["nested"].(map[string]any)
	if nested["secret_value"] != "[REDACTED]" {
		t.Error("nested secret should be redacted")
	}
	if nested["public_value"] != "shown" {
		t.Error("nested public value should not be redacted")
	}
}

func TestDiagnosticCollector_WriteJSON(t *testing.T) {
	client := &mockClient{}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client: client,
		Output: buf,
	})

	ctx := context.Background()
	report, _ := collector.Collect(ctx)

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := collector.WriteReport(report, path); err != nil {
		t.Fatalf("WriteReport error: %v", err)
	}

	// Read and parse
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	var loaded DiagnosticReport
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if loaded.Version != report.Version {
		t.Error("version mismatch")
	}
}

func TestDiagnosticCollector_WriteTarGz(t *testing.T) {
	client := &mockClient{
		status:  &Status{Version: "1.0.0"},
		metrics: &Metrics{SessionsTotal: 10},
		config:  map[string]any{"key": "value"},
		sessions: []SessionInfo{{ID: "sess-1"}},
	}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client: client,
		Output: buf,
	})

	ctx := context.Background()
	report, _ := collector.Collect(ctx)

	dir := t.TempDir()
	path := filepath.Join(dir, "report.tar.gz")

	if err := collector.WriteReport(report, path); err != nil {
		t.Fatalf("WriteReport error: %v", err)
	}

	// Verify file exists
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat error: %v", err)
	}

	if info.Size() == 0 {
		t.Error("tar.gz file should not be empty")
	}
}

func TestDiagnosticCollector_GenerateReport(t *testing.T) {
	client := &mockClient{
		status:  &Status{Version: "1.0.0"},
		metrics: &Metrics{},
		config:  map[string]any{},
	}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client: client,
		Output: buf,
	})

	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	ctx := context.Background()
	if err := collector.GenerateReport(ctx, path); err != nil {
		t.Fatalf("GenerateReport error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("should have output")
	}

	// Check progress messages
	if output == "" {
		t.Error("should show progress")
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{500, "500 bytes"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		got := formatSize(tt.bytes)
		if got != tt.want {
			t.Errorf("formatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestDiagnosticCollector_CollectWithErrors(t *testing.T) {
	// Client that returns errors for some operations
	client := &mockClient{
		status: nil, // Will cause error
	}
	buf := &bytes.Buffer{}

	collector := NewDiagnosticCollector(DiagnosticConfig{
		Client: client,
		Output: buf,
	})

	ctx := context.Background()
	report, err := collector.Collect(ctx)

	// Should still succeed, just with errors recorded
	if err != nil {
		t.Fatalf("Collect should not error: %v", err)
	}

	// System info should still be collected
	if report.SystemInfo.OS == "" {
		t.Error("should have system info even with other errors")
	}
}
