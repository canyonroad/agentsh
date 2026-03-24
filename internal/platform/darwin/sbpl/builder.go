// Package sbpl constructs valid SBPL (Sandbox Profile Language) strings
// via a typed Go API. It is pure Go with no CGo or build tags so that
// tests can run on any OS.
package sbpl

import (
	"fmt"
	"strings"
)

// PathMatch controls how a path argument is matched in an SBPL rule.
type PathMatch int

const (
	Literal PathMatch = iota // (literal "/exact/path")
	Subpath                  // (subpath "/dir")
	Regex                    // (regex #"/pattern"#)
)

// ruleKind groups rules for deterministic ordering in the output.
type ruleKind int

const (
	kindFileAllow ruleKind = iota
	kindFileDeny
	kindExecAllow
	kindExecDeny
	kindMachAllow
	kindMachDeny
	kindNetworkAllow
	kindNetworkDeny
	kindOther
)

// rule is a single SBPL statement with its kind for ordering.
type rule struct {
	kind ruleKind
	sbpl string
}

// Profile accumulates SBPL rules and renders them into a complete
// sandbox profile string.
type Profile struct {
	rules []rule
}

// New creates an empty Profile.
func New() *Profile {
	return &Profile{}
}

// AllowFileRead adds a rule allowing file-read* for the given path.
func (p *Profile) AllowFileRead(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* (%s %s))", matchStr(match), quotePath(path)),
	})
}

// AllowFileReadWrite adds a rule allowing file-read* and file-write*
// for the given path.
func (p *Profile) AllowFileReadWrite(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* (%s %s))", matchStr(match), quotePath(path)),
	})
}

// AllowFileReadWriteIOctl adds a rule allowing file-read*, file-write*,
// and file-ioctl for the given path.
func (p *Profile) AllowFileReadWriteIOctl(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* file-ioctl (%s %s))", matchStr(match), quotePath(path)),
	})
}

// Build renders the accumulated rules into a complete SBPL profile string.
// It returns an error if any non-regex path is relative.
func (p *Profile) Build() (string, error) {
	for _, r := range p.rules {
		if err := validateRule(r); err != nil {
			return "", err
		}
	}

	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")

	// Emit deny rules before allow rules for readability.
	for _, r := range p.rules {
		if isDeny(r.kind) {
			b.WriteString(r.sbpl)
			b.WriteByte('\n')
		}
	}
	for _, r := range p.rules {
		if !isDeny(r.kind) {
			b.WriteString(r.sbpl)
			b.WriteByte('\n')
		}
	}

	return b.String(), nil
}

// isDeny returns true for deny-class rule kinds.
func isDeny(k ruleKind) bool {
	switch k {
	case kindFileDeny, kindExecDeny, kindMachDeny, kindNetworkDeny:
		return true
	default:
		return false
	}
}

// matchStr returns the SBPL match keyword for the given PathMatch.
func matchStr(m PathMatch) string {
	switch m {
	case Literal:
		return "literal"
	case Subpath:
		return "subpath"
	case Regex:
		return "regex"
	default:
		return "literal"
	}
}

// quotePath escapes backslashes and quotes in a path and wraps it in
// double quotes. Regex patterns (starting with #") are passed through
// unchanged.
func quotePath(path string) string {
	if strings.HasPrefix(path, `#"`) {
		return path // regex pattern, pass through
	}
	escaped := strings.ReplaceAll(path, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// validateRule checks that non-regex paths in a rule are absolute.
func validateRule(r rule) error {
	// Extract the path from the SBPL string for validation.
	// Rules follow the pattern: (allow ... (match "path"))
	// or for regex: (allow ... (regex #"pattern"#))

	// If it's a regex rule, skip validation.
	if strings.Contains(r.sbpl, "(regex ") {
		return nil
	}

	// Extract the quoted path from the rule.
	// Find the last quoted string in the rule.
	lastQuote := strings.LastIndex(r.sbpl, `"`)
	if lastQuote < 0 {
		return nil
	}

	// Walk backward to find the opening quote.
	openQuote := -1
	for i := lastQuote - 1; i >= 0; i-- {
		if r.sbpl[i] == '"' && (i == 0 || r.sbpl[i-1] != '\\') {
			openQuote = i
			break
		}
	}
	if openQuote < 0 {
		return nil
	}

	path := r.sbpl[openQuote+1 : lastQuote]
	// Unescape for validation.
	path = strings.ReplaceAll(path, `\"`, `"`)
	path = strings.ReplaceAll(path, `\\`, `\`)

	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sbpl: path must be absolute, got %q", path)
	}
	return nil
}
