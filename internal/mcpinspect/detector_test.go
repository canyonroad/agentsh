package mcpinspect

import (
	"testing"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("NewDetector returned nil")
	}
	// Note: patterns will be nil/empty until built-in patterns are added in subsequent tasks.
	// This test verifies the detector can be created successfully.
	if d.patterns == nil {
		t.Error("NewDetector should initialize patterns slice")
	}
}

func TestDetector_InspectCleanTool(t *testing.T) {
	d := NewDetector()
	tool := ToolDefinition{
		Name:        "read_file",
		Description: "Reads a file from the filesystem.",
	}

	results := d.Inspect(tool)
	if len(results) != 0 {
		t.Errorf("expected no detections for clean tool, got %d", len(results))
	}
}
