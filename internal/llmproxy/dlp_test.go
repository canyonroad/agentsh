package llmproxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestDLPProcessor_RedactEmail(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	// Test plain text
	input := []byte("Contact us at support@example.com for help")
	result := processor.Process(input, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	expected := "Contact us at [REDACTED:email] for help"
	if string(result.ProcessedData) != expected {
		t.Errorf("expected %q, got %q", expected, string(result.ProcessedData))
	}

	if len(result.Redactions) != 1 {
		t.Fatalf("expected 1 redaction, got %d", len(result.Redactions))
	}

	if result.Redactions[0].Type != "email" {
		t.Errorf("expected redaction type 'email', got %q", result.Redactions[0].Type)
	}

	if result.Redactions[0].Count != 1 {
		t.Errorf("expected count 1, got %d", result.Redactions[0].Count)
	}
}

func TestDLPProcessor_RedactEmail_JSON(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	// Test JSON with email in nested field
	input := []byte(`{"messages":[{"role":"user","content":"Email me at john@example.com"}]}`)
	result := processor.Process(input, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	// Verify the redaction was applied
	if !strings.Contains(string(result.ProcessedData), "[REDACTED:email]") {
		t.Errorf("expected redacted email in output, got %q", string(result.ProcessedData))
	}

	// Verify the field path is tracked
	if len(result.Redactions) != 1 {
		t.Fatalf("expected 1 redaction, got %d", len(result.Redactions))
	}

	// Field path should be something like "messages[0].content"
	if result.Redactions[0].Field == "" {
		t.Error("expected field path to be non-empty")
	}
}

func TestDLPProcessor_CustomPattern(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		CustomPatterns: []config.CustomPatternConfig{
			{
				Name:    "internal_customer_id", // For logs
				Display: "identifier",           // Sent to LLM as [REDACTED:identifier]
				Regex:   `CUST-[0-9]{8}`,
			},
		},
	}

	processor := NewDLPProcessor(cfg)

	input := []byte("Customer CUST-12345678 placed an order")
	result := processor.Process(input, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	// Redaction in output should use the Display name
	expected := "Customer [REDACTED:identifier] placed an order"
	if string(result.ProcessedData) != expected {
		t.Errorf("expected %q, got %q", expected, string(result.ProcessedData))
	}

	if len(result.Redactions) != 1 {
		t.Fatalf("expected 1 redaction, got %d", len(result.Redactions))
	}

	// Redaction type in result should use the internal Name (for logs)
	if result.Redactions[0].Type != "internal_customer_id" {
		t.Errorf("expected redaction type 'internal_customer_id' (internal name), got %q", result.Redactions[0].Type)
	}
}

func TestDLPProcessor_Disabled(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "disabled",
		Patterns: config.DLPPatternsConfig{
			Email:      true,
			Phone:      true,
			CreditCard: true,
			SSN:        true,
			APIKeys:    true,
		},
	}

	processor := NewDLPProcessor(cfg)

	input := []byte("Contact us at support@example.com or call 555-123-4567")
	result := processor.Process(input, DialectAnthropic)

	if result.Modified {
		t.Error("expected Modified to be false when disabled")
	}

	// Data should pass through unchanged
	if string(result.ProcessedData) != string(input) {
		t.Errorf("expected passthrough, got %q", string(result.ProcessedData))
	}

	if len(result.Redactions) != 0 {
		t.Errorf("expected 0 redactions when disabled, got %d", len(result.Redactions))
	}
}

func TestDLPProcessor_MultiplePatterns(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
			Phone: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	input := []byte("Contact: user@test.com, phone: 555-123-4567")
	result := processor.Process(input, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	// Both should be redacted
	output := string(result.ProcessedData)
	if !strings.Contains(output, "[REDACTED:email]") {
		t.Error("expected email to be redacted")
	}
	if !strings.Contains(output, "[REDACTED:phone]") {
		t.Error("expected phone to be redacted")
	}

	// Should have 2 redaction entries
	if len(result.Redactions) != 2 {
		t.Errorf("expected 2 redactions, got %d", len(result.Redactions))
	}
}

func TestDLPProcessor_SSN(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			SSN: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	testCases := []struct {
		input    string
		expected string
	}{
		{"SSN: 123-45-6789", "SSN: [REDACTED:ssn]"},
		{"SSN: 123 45 6789", "SSN: [REDACTED:ssn]"},
		{"SSN: 123456789", "SSN: [REDACTED:ssn]"},
	}

	for _, tc := range testCases {
		result := processor.Process([]byte(tc.input), DialectAnthropic)
		if string(result.ProcessedData) != tc.expected {
			t.Errorf("input %q: expected %q, got %q", tc.input, tc.expected, string(result.ProcessedData))
		}
	}
}

func TestDLPProcessor_CreditCard(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			CreditCard: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	testCases := []struct {
		input string
	}{
		{"Card: 4111111111111111"},
		{"Card: 4111-1111-1111-1111"},
		{"Card: 4111 1111 1111 1111"},
	}

	for _, tc := range testCases {
		result := processor.Process([]byte(tc.input), DialectAnthropic)
		if !result.Modified {
			t.Errorf("input %q: expected Modified to be true", tc.input)
		}
		if !strings.Contains(string(result.ProcessedData), "[REDACTED:credit_card]") {
			t.Errorf("input %q: expected credit card redaction, got %q", tc.input, string(result.ProcessedData))
		}
	}
}

func TestDLPProcessor_APIKeys(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			APIKeys: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	testCases := []struct {
		input string
	}{
		// sk followed by 20+ alphanumeric chars
		{"key: sk_abcdefghij1234567890abcd"},
		// api followed by 20+ alphanumeric chars
		{"api_abcdefghij1234567890abcdef"},
		// secret followed by 20+ alphanumeric chars
		{"SECRET_abcdefghij1234567890ab"},
		// token followed by 20+ alphanumeric chars
		{"token-abcdefghij1234567890abc"},
	}

	for _, tc := range testCases {
		result := processor.Process([]byte(tc.input), DialectAnthropic)
		if !result.Modified {
			t.Errorf("input %q: expected Modified to be true", tc.input)
		}
		if !strings.Contains(string(result.ProcessedData), "[REDACTED:api_key]") {
			t.Errorf("input %q: expected API key redaction, got %q", tc.input, string(result.ProcessedData))
		}
	}
}

func TestDLPProcessor_NoPatterns(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		// All patterns disabled by default (zero values)
	}

	processor := NewDLPProcessor(cfg)

	input := []byte("Contact us at support@example.com")
	result := processor.Process(input, DialectAnthropic)

	if result.Modified {
		t.Error("expected Modified to be false when no patterns enabled")
	}

	if string(result.ProcessedData) != string(input) {
		t.Errorf("expected passthrough when no patterns, got %q", string(result.ProcessedData))
	}
}

func TestDLPProcessor_DuplicateMatches(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	// Same email appears twice
	input := []byte("Contact test@example.com or test@example.com")
	result := processor.Process(input, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	// Count should be 1 for unique matches
	if len(result.Redactions) != 1 {
		t.Fatalf("expected 1 redaction entry, got %d", len(result.Redactions))
	}

	if result.Redactions[0].Count != 1 {
		t.Errorf("expected count 1 for unique matches, got %d", result.Redactions[0].Count)
	}

	// Both instances should be redacted
	expected := "Contact [REDACTED:email] or [REDACTED:email]"
	if string(result.ProcessedData) != expected {
		t.Errorf("expected %q, got %q", expected, string(result.ProcessedData))
	}
}

func TestDLPProcessor_NestedJSON(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		Patterns: config.DLPPatternsConfig{
			Email: true,
		},
	}

	processor := NewDLPProcessor(cfg)

	input := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": "My email is user@test.com",
			},
		},
		"metadata": map[string]interface{}{
			"author": "author@company.org",
		},
	}

	inputBytes, _ := json.Marshal(input)
	result := processor.Process(inputBytes, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	// Both emails should be redacted
	output := string(result.ProcessedData)
	if strings.Contains(output, "user@test.com") {
		t.Error("user@test.com should be redacted")
	}
	if strings.Contains(output, "author@company.org") {
		t.Error("author@company.org should be redacted")
	}

	// Should have 2 redaction entries (different fields)
	if len(result.Redactions) != 2 {
		t.Errorf("expected 2 redactions (one per field), got %d", len(result.Redactions))
	}
}

func TestDLPProcessor_CustomPatternWithNoDisplay(t *testing.T) {
	// When Display is empty, use Name for both
	cfg := config.DLPConfig{
		Mode: "redact",
		CustomPatterns: []config.CustomPatternConfig{
			{
				Name:    "project_code",
				Display: "", // Empty display - should fall back to name
				Regex:   `PRJ-[A-Z]{3}-[0-9]{4}`,
			},
		},
	}

	processor := NewDLPProcessor(cfg)

	input := []byte("Working on PRJ-ABC-1234")
	result := processor.Process(input, DialectAnthropic)

	if !result.Modified {
		t.Error("expected Modified to be true")
	}

	// Should use name as display when display is empty
	expected := "Working on [REDACTED:project_code]"
	if string(result.ProcessedData) != expected {
		t.Errorf("expected %q, got %q", expected, string(result.ProcessedData))
	}
}

func TestDLPProcessor_InvalidRegex(t *testing.T) {
	cfg := config.DLPConfig{
		Mode: "redact",
		CustomPatterns: []config.CustomPatternConfig{
			{
				Name:    "invalid",
				Display: "invalid",
				Regex:   `[invalid`, // Invalid regex
			},
			{
				Name:    "valid",
				Display: "valid_pattern",
				Regex:   `VALID-[0-9]+`,
			},
		},
	}

	// Should not panic, should skip invalid pattern
	processor := NewDLPProcessor(cfg)

	input := []byte("Test VALID-123")
	result := processor.Process(input, DialectAnthropic)

	// Valid pattern should still work
	if !result.Modified {
		t.Error("expected Modified to be true for valid pattern")
	}

	if !strings.Contains(string(result.ProcessedData), "[REDACTED:valid_pattern]") {
		t.Errorf("expected valid pattern redaction, got %q", string(result.ProcessedData))
	}
}
