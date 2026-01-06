package mcpinspect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// CompiledPattern is a pre-compiled detection pattern.
type CompiledPattern struct {
	Name        string
	Category    string
	Severity    Severity
	Regex       *regexp.Regexp
	Description string
}

// Detector scans tool definitions for suspicious patterns.
type Detector struct {
	patterns []CompiledPattern
}

// NewDetector creates a detector with built-in patterns.
func NewDetector() *Detector {
	return &Detector{
		patterns: compileBuiltinPatterns(),
	}
}

// Inspect scans a tool definition and returns any detections.
func (d *Detector) Inspect(tool ToolDefinition) []DetectionResult {
	var results []DetectionResult

	// Inspect description
	descResults := d.inspectText(tool.Description, "description")
	results = append(results, descResults...)

	// Inspect input schema
	schemaResults := d.inspectSchema(tool.InputSchema)
	results = append(results, schemaResults...)

	// Sort by severity (critical first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Severity > results[j].Severity
	})

	return results
}

func (d *Detector) inspectText(text, field string) []DetectionResult {
	if text == "" {
		return nil
	}

	var results []DetectionResult
	for _, pattern := range d.patterns {
		matches := pattern.Regex.FindAllStringIndex(text, -1)
		if len(matches) == 0 {
			continue
		}

		var matchDetails []Match
		for _, m := range matches {
			start := max(0, m[0]-50)
			end := min(len(text), m[1]+50)
			matchDetails = append(matchDetails, Match{
				Text:     text[m[0]:m[1]],
				Position: m[0],
				Context:  text[start:end],
			})
		}

		results = append(results, DetectionResult{
			Pattern:  pattern.Name,
			Category: pattern.Category,
			Severity: pattern.Severity,
			Matches:  matchDetails,
			Field:    field,
		})
	}

	return results
}

func (d *Detector) inspectSchema(schema []byte) []DetectionResult {
	if len(schema) == 0 {
		return nil
	}

	var results []DetectionResult
	var schemaData map[string]interface{}
	if err := json.Unmarshal(schema, &schemaData); err != nil {
		return results
	}

	d.inspectSchemaNode(schemaData, "inputSchema", &results)
	return results
}

func (d *Detector) inspectSchemaNode(node interface{}, path string, results *[]DetectionResult) {
	switch v := node.(type) {
	case string:
		textResults := d.inspectText(v, path)
		*results = append(*results, textResults...)
	case map[string]interface{}:
		for key, val := range v {
			d.inspectSchemaNode(val, path+"."+key, results)
		}
	case []interface{}:
		for i, val := range v {
			d.inspectSchemaNode(val, fmt.Sprintf("%s[%d]", path, i), results)
		}
	}
}

// compileBuiltinPatterns returns an empty slice for now - patterns added in subsequent tasks.
func compileBuiltinPatterns() []CompiledPattern {
	patterns := []CompiledPattern{}

	// Credential theft patterns (critical severity)
	credentialPatterns := []struct {
		name    string
		pattern string
	}{
		{"ssh_key", `~?/?\.ssh/id_`},
		{"ssh_dir", `~/?\.ssh`},
		{"env_file", `\.env\b`},
		{"credentials", `(?i)credentials?\.`},
		{"api_key", `(?i)api[_-]?key`},
		{"secret_key", `(?i)secret[_-]?key`},
		{"access_token", `(?i)access[_-]?token`},
		{"private_key", `(?i)private[_-]?key`},
		{"passwd_file", `/etc/passwd`},
		{"shadow_file", `/etc/shadow`},
	}

	for _, p := range credentialPatterns {
		if re, err := regexp.Compile(p.pattern); err == nil {
			patterns = append(patterns, CompiledPattern{
				Name:        p.name,
				Category:    "credential_theft",
				Severity:    SeverityCritical,
				Regex:       re,
				Description: "Potential credential theft pattern",
			})
		}
	}

	// Exfiltration patterns (high severity)
	exfilPatterns := []struct {
		name    string
		pattern string
	}{
		{"curl_upload", `curl\s+.*https?://`},
		{"wget", `wget\s+`},
		{"netcat", `\bnc\s+-`},
		{"netcat_full", `netcat`},
		{"base64_curl", `base64.*\|.*curl`},
		{"pipe_curl", `\|\s*curl`},
	}

	for _, p := range exfilPatterns {
		if re, err := regexp.Compile(p.pattern); err == nil {
			patterns = append(patterns, CompiledPattern{
				Name:        p.name,
				Category:    "exfiltration",
				Severity:    SeverityHigh,
				Regex:       re,
				Description: "Potential data exfiltration pattern",
			})
		}
	}

	// Hidden instructions patterns (high severity)
	hiddenPatterns := []struct {
		name    string
		pattern string
	}{
		// Match IMPORTANT: followed by action verbs that suggest command injection
		{"important_suspicious", `(?i)IMPORTANT:\s*(before|first|always|never|must|do|copy|send|upload|download|execute|run|delete|remove)`},
		{"hidden_directive", `(?i)HIDDEN:`},
		{"secret_directive", `(?i)SECRET:`},
		{"do_not_show", `(?i)DO\s+NOT\s+SHOW`},
		{"ignore_previous", `(?i)IGNORE\s+PREVIOUS`},
		{"system_override", `(?i)SYSTEM\s+OVERRIDE`},
	}

	for _, p := range hiddenPatterns {
		if re, err := regexp.Compile(p.pattern); err == nil {
			patterns = append(patterns, CompiledPattern{
				Name:        p.name,
				Category:    "hidden_instructions",
				Severity:    SeverityHigh,
				Regex:       re,
				Description: "Potential hidden instruction injection",
			})
		}
	}

	return patterns
}
