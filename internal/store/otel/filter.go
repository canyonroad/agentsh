package otel

import (
	"path"
)

// Filter controls which events are exported via OTEL.
type Filter struct {
	IncludeTypes      []string
	ExcludeTypes      []string
	IncludeCategories []string
	ExcludeCategories []string
	MinRiskLevel      string
}

// riskLevels maps risk level strings to numeric values for comparison.
var riskLevels = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Match returns true if the event should be exported.
func (f *Filter) Match(eventType, category, riskLevel string) bool {
	if f == nil {
		return true
	}

	// Include type filter: if set, event type must match at least one pattern.
	if len(f.IncludeTypes) > 0 {
		matched := false
		for _, pattern := range f.IncludeTypes {
			if ok, _ := path.Match(pattern, eventType); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Include category filter: if set, category must be in the list.
	if len(f.IncludeCategories) > 0 {
		found := false
		for _, c := range f.IncludeCategories {
			if c == category {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Exclude type filter.
	for _, pattern := range f.ExcludeTypes {
		if ok, _ := path.Match(pattern, eventType); ok {
			return false
		}
	}

	// Exclude category filter.
	for _, c := range f.ExcludeCategories {
		if c == category {
			return false
		}
	}

	// Min risk level filter.
	if f.MinRiskLevel != "" {
		threshold := riskLevels[f.MinRiskLevel]
		actual := riskLevels[riskLevel]
		if actual < threshold {
			return false
		}
	}

	return true
}
