package otel

import (
	"testing"
)

func TestFilter_NilPassesAll(t *testing.T) {
	var f *Filter
	if !f.Match("file_write", "file", "high") {
		t.Error("nil filter should pass all events")
	}
}

func TestFilter_EmptyPassesAll(t *testing.T) {
	f := &Filter{}
	if !f.Match("file_write", "file", "") {
		t.Error("empty filter should pass all events")
	}
}

func TestFilter_IncludeTypes(t *testing.T) {
	f := &Filter{IncludeTypes: []string{"file_*", "net_*"}}

	tests := []struct {
		eventType string
		want      bool
	}{
		{"file_write", true},
		{"file_read", true},
		{"net_connect", true},
		{"process_start", false},
		{"dns_query", false},
	}
	for _, tt := range tests {
		if got := f.Match(tt.eventType, "", ""); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.eventType, got, tt.want)
		}
	}
}

func TestFilter_ExcludeTypes(t *testing.T) {
	f := &Filter{ExcludeTypes: []string{"file_stat", "dir_list"}}

	tests := []struct {
		eventType string
		want      bool
	}{
		{"file_write", true},
		{"file_stat", false},
		{"dir_list", false},
		{"net_connect", true},
	}
	for _, tt := range tests {
		if got := f.Match(tt.eventType, "", ""); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.eventType, got, tt.want)
		}
	}
}

func TestFilter_IncludeCategories(t *testing.T) {
	f := &Filter{IncludeCategories: []string{"file", "network"}}

	tests := []struct {
		category string
		want     bool
	}{
		{"file", true},
		{"network", true},
		{"process", false},
		{"signal", false},
	}
	for _, tt := range tests {
		if got := f.Match("any", tt.category, ""); got != tt.want {
			t.Errorf("Match(category=%q) = %v, want %v", tt.category, got, tt.want)
		}
	}
}

func TestFilter_ExcludeCategories(t *testing.T) {
	f := &Filter{ExcludeCategories: []string{"environment"}}

	tests := []struct {
		category string
		want     bool
	}{
		{"file", true},
		{"environment", false},
	}
	for _, tt := range tests {
		if got := f.Match("any", tt.category, ""); got != tt.want {
			t.Errorf("Match(category=%q) = %v, want %v", tt.category, got, tt.want)
		}
	}
}

func TestFilter_MinRiskLevel(t *testing.T) {
	f := &Filter{MinRiskLevel: "medium"}

	tests := []struct {
		risk string
		want bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", true},
		{"low", false},
		{"", true}, // no risk level = passes through (threshold only applies to events that carry one)
	}
	for _, tt := range tests {
		if got := f.Match("any", "any", tt.risk); got != tt.want {
			t.Errorf("Match(risk=%q) = %v, want %v", tt.risk, got, tt.want)
		}
	}
}

func TestFilter_Combined(t *testing.T) {
	f := &Filter{
		IncludeCategories: []string{"file", "network"},
		ExcludeTypes:      []string{"file_stat"},
	}

	tests := []struct {
		eventType string
		category  string
		want      bool
	}{
		{"file_write", "file", true},
		{"file_stat", "file", false},        // excluded by type
		{"net_connect", "network", true},
		{"process_start", "process", false}, // not in included categories
	}
	for _, tt := range tests {
		if got := f.Match(tt.eventType, tt.category, ""); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.eventType, tt.category, got, tt.want)
		}
	}
}
