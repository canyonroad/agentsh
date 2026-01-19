//go:build linux || darwin || windows

package capabilities

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DetectResult is the unified cross-platform detection result.
type DetectResult struct {
	Platform        string         `json:"platform" yaml:"platform"`
	SecurityMode    string         `json:"security_mode" yaml:"security_mode"`
	ProtectionScore int            `json:"protection_score" yaml:"protection_score"`
	Capabilities    map[string]any `json:"capabilities" yaml:"capabilities"`
	Summary         DetectSummary  `json:"summary" yaml:"summary"`
	Tips            []Tip          `json:"tips" yaml:"tips"`
}

// DetectSummary provides a quick overview of available/unavailable features.
type DetectSummary struct {
	Available   []string `json:"available" yaml:"available"`
	Unavailable []string `json:"unavailable" yaml:"unavailable"`
}

// Tip provides actionable guidance for enabling a capability.
type Tip struct {
	Feature string `json:"feature" yaml:"feature"`
	Status  string `json:"status" yaml:"status"`
	Impact  string `json:"impact" yaml:"impact"`
	Action  string `json:"action" yaml:"action"`
}

// JSON returns the detection result as JSON bytes.
func (r *DetectResult) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// YAML returns the detection result as YAML bytes.
func (r *DetectResult) YAML() ([]byte, error) {
	return yaml.Marshal(r)
}

// Table returns a human-readable table representation.
func (r *DetectResult) Table() string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("Platform: %s\n", r.Platform))
	sb.WriteString(fmt.Sprintf("Security Mode: %s\n", r.SecurityMode))
	sb.WriteString(fmt.Sprintf("Protection Score: %d%%\n", r.ProtectionScore))
	sb.WriteString("\n")

	// Capabilities table
	sb.WriteString("CAPABILITIES\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")

	// Sort capability keys for consistent output
	keys := make([]string, 0, len(r.Capabilities))
	for k := range r.Capabilities {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := r.Capabilities[k]
		status := formatCapabilityValue(v)
		sb.WriteString(fmt.Sprintf("  %-24s %s\n", k, status))
	}

	// Tips section
	if len(r.Tips) > 0 {
		sb.WriteString("\nTIPS\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for _, tip := range r.Tips {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", tip.Feature, tip.Impact))
			sb.WriteString(fmt.Sprintf("    -> %s\n", tip.Action))
		}
	}

	sb.WriteString("\nRun 'agentsh detect config' to generate an optimized configuration.\n")

	return sb.String()
}

func formatCapabilityValue(v any) string {
	switch val := v.(type) {
	case bool:
		if val {
			return "✓"
		}
		return "-"
	case int:
		return fmt.Sprintf("✓ (v%d)", val)
	case string:
		return val
	default:
		return fmt.Sprintf("%v", v)
	}
}
