package mcpinspect

import (
	"testing"
)

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
		{"server-git", "server-glt", 1},
	}
	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestNormalizedSimilarity(t *testing.T) {
	tests := []struct {
		a, b      string
		wantAbove float64
		wantBelow float64
	}{
		{"server-git", "server-git", 1.0, 1.01},
		{"server-git", "server-glt", 0.89, 0.91},
		{"modelcontextprotocol", "modelcontextprotoco1", 0.94, 0.96},
		{"abc", "xyz", -0.01, 0.01},
	}
	for _, tt := range tests {
		got := NormalizedSimilarity(tt.a, tt.b)
		if got < tt.wantAbove || got > tt.wantBelow {
			t.Errorf("NormalizedSimilarity(%q, %q) = %f, want [%f, %f]", tt.a, tt.b, got, tt.wantAbove, tt.wantBelow)
		}
	}
}

func TestCheckServerNameSimilarity(t *testing.T) {
	existing := []string{"server-git", "server-postgres", "weather-api"}

	tests := []struct {
		name      string
		newID     string
		threshold float64
		wantMatch string
	}{
		{"exact match", "server-git", 0.85, "server-git"},
		{"typo", "server-glt", 0.85, "server-git"},
		{"no match", "totally-different", 0.85, ""},
		{"similar to postgres", "server-postgras", 0.85, "server-postgres"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, _ := CheckServerNameSimilarity(tt.newID, existing, tt.threshold)
			if match != tt.wantMatch {
				t.Errorf("match = %q, want %q", match, tt.wantMatch)
			}
		})
	}
}
