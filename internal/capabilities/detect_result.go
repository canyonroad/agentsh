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
	Platform        string             `json:"platform" yaml:"platform"`
	SecurityMode    string             `json:"security_mode" yaml:"security_mode"`
	ProtectionScore int                `json:"protection_score" yaml:"protection_score"`
	Domains         []ProtectionDomain `json:"domains" yaml:"domains"`
	Capabilities    map[string]any     `json:"capabilities" yaml:"capabilities"`
	Summary         DetectSummary      `json:"summary" yaml:"summary"`
	Tips            []Tip              `json:"tips" yaml:"tips"`
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

// ProbeResult holds the result of a capability probe.
type ProbeResult struct {
	Available bool   `json:"available" yaml:"available"`
	Detail    string `json:"detail" yaml:"detail"`
}

// ProtectionDomain groups related security backends by what they protect.
type ProtectionDomain struct {
	Name     string            `json:"name" yaml:"name"`
	Weight   int               `json:"weight" yaml:"weight"`
	Score    int               `json:"score" yaml:"score"`
	Backends []DetectedBackend `json:"backends" yaml:"backends"`
	Active   string            `json:"active" yaml:"active"`
}

// DetectedBackend represents a single security mechanism within a domain.
type DetectedBackend struct {
	Name        string `json:"name" yaml:"name"`
	Available   bool   `json:"available" yaml:"available"`
	Detail      string `json:"detail" yaml:"detail"`
	Description string `json:"description" yaml:"description"`
	CheckMethod string `json:"check_method" yaml:"check_method"`
}

// Domain weight constants.
const (
	WeightFileProtection = 25
	WeightCommandControl = 25
	WeightNetwork        = 20
	WeightResourceLimits = 15
	WeightIsolation      = 15
)

// ComputeScore calculates the protection score from domain availability.
// Each domain scores its full weight if ANY backend is available, 0 otherwise.
func ComputeScore(domains []ProtectionDomain) int {
	score := 0
	for i := range domains {
		hasAny := false
		for _, b := range domains[i].Backends {
			if b.Available {
				hasAny = true
				break
			}
		}
		if hasAny {
			domains[i].Score = domains[i].Weight
		} else {
			domains[i].Score = 0
		}
		score += domains[i].Score
	}
	return score
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

	sb.WriteString(fmt.Sprintf("Platform:         %s\n", r.Platform))
	sb.WriteString(fmt.Sprintf("Security Mode:    %s\n", r.SecurityMode))
	sb.WriteString(fmt.Sprintf("Protection Score: %d/100\n", r.ProtectionScore))
	sb.WriteString("\n")

	// Render domains if available (new format)
	if len(r.Domains) > 0 {
		for _, d := range r.Domains {
			sb.WriteString(fmt.Sprintf("%-40s %d/%d\n", strings.ToUpper(d.Name), d.Score, d.Weight))
			for _, b := range d.Backends {
				status := "-"
				if b.Available {
					status = "✓"
				}
				detail := b.Detail
				if detail == "" {
					detail = " "
				}
				sb.WriteString(fmt.Sprintf("  %-20s %s  %-16s %s\n", b.Name, status, detail, b.Description))
			}
			if d.Active != "" && d.Active != "none" {
				sb.WriteString(fmt.Sprintf("  active backend:    %s\n", d.Active))
			}
			sb.WriteString("\n")
		}
	} else {
		// Fallback: flat capabilities (backward compat for platforms not yet converted)
		sb.WriteString("CAPABILITIES\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
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
		sb.WriteString("\n")
	}

	if len(r.Tips) > 0 {
		sb.WriteString("TIPS\n")
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
