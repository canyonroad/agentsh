package report

import (
	"testing"
)

func TestFindingSeverity(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityWarning, "warning"},
		{SeverityInfo, "info"},
	}
	for _, tc := range tests {
		if string(tc.sev) != tc.want {
			t.Errorf("Severity %v != %q", tc.sev, tc.want)
		}
	}
}

func TestReportLevel(t *testing.T) {
	if LevelSummary != "summary" {
		t.Error("LevelSummary should be 'summary'")
	}
	if LevelDetailed != "detailed" {
		t.Error("LevelDetailed should be 'detailed'")
	}
}
