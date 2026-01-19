//go:build linux || darwin || windows

package capabilities

import (
	"encoding/json"

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
