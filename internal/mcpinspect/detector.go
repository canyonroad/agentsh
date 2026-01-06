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
	return []CompiledPattern{}
}
