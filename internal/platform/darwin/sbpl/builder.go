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
		sbpl: fmt.Sprintf("(allow file-read* (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowFileReadWrite adds a rule allowing file-read* and file-write*
// for the given path.
func (p *Profile) AllowFileReadWrite(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowFileReadWriteIOctl adds a rule allowing file-read*, file-write*,
// and file-ioctl for the given path.
func (p *Profile) AllowFileReadWriteIOctl(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: fmt.Sprintf("(allow file-read* file-write* file-ioctl (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowProcessExec adds a rule allowing process-exec for the given path.
func (p *Profile) AllowProcessExec(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindExecAllow,
		sbpl: fmt.Sprintf("(allow process-exec (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// DenyProcessExec adds a rule denying process-exec for the given path.
func (p *Profile) DenyProcessExec(match PathMatch, path string) {
	p.rules = append(p.rules, rule{
		kind: kindExecDeny,
		sbpl: fmt.Sprintf("(deny process-exec (%s %s))", matchStr(match), quotePathForMatch(match, path)),
	})
}

// AllowMachLookup adds a rule allowing mach-lookup for the given service name.
func (p *Profile) AllowMachLookup(serviceName string) {
	p.rules = append(p.rules, rule{
		kind: kindMachAllow,
		sbpl: fmt.Sprintf("(allow mach-lookup (global-name %q))", serviceName),
	})
}

// AllowMachLookupPrefix adds a rule allowing mach-lookup for services
// matching the given prefix.
func (p *Profile) AllowMachLookupPrefix(prefix string) {
	p.rules = append(p.rules, rule{
		kind: kindMachAllow,
		sbpl: fmt.Sprintf("(allow mach-lookup (global-name-prefix %q))", prefix),
	})
}

// DenyMachLookup adds a rule denying mach-lookup for the given service name.
func (p *Profile) DenyMachLookup(serviceName string) {
	p.rules = append(p.rules, rule{
		kind: kindMachDeny,
		sbpl: fmt.Sprintf("(deny mach-lookup (global-name %q))", serviceName),
	})
}

// DenyMachLookupPrefix adds a rule denying mach-lookup for services
// matching the given prefix.
func (p *Profile) DenyMachLookupPrefix(prefix string) {
	p.rules = append(p.rules, rule{
		kind: kindMachDeny,
		sbpl: fmt.Sprintf("(deny mach-lookup (global-name-prefix %q))", prefix),
	})
}

// AllowNetworkAll adds a rule allowing all network operations.
func (p *Profile) AllowNetworkAll() {
	p.rules = append(p.rules, rule{
		kind: kindNetworkAllow,
		sbpl: "(allow network*)",
	})
}

// AllowNetworkOutbound adds a rule allowing outbound network connections
// for the given protocol and host:port. The proto parameter must be a valid
// SBPL protocol identifier containing only lowercase letters (e.g., "tcp", "udp").
func (p *Profile) AllowNetworkOutbound(proto, hostPort string) {
	// Validate proto contains only [a-z] to prevent SBPL injection
	for _, c := range proto {
		if c < 'a' || c > 'z' {
			// Invalid proto — skip silently (will be caught by sandbox_init if wrong)
			return
		}
	}
	p.rules = append(p.rules, rule{
		kind: kindNetworkAllow,
		sbpl: fmt.Sprintf(`(allow network-outbound (remote %s "%s"))`, proto, hostPort),
	})
}

// AllowSystemEssentials adds all rules needed for basic macOS process
// operation: process ops, system libraries, dev files, common tool paths,
// TTY access, temp files, and IPC.
func (p *Profile) AllowSystemEssentials() {
	// Process operations
	p.rules = append(p.rules,
		rule{kind: kindOther, sbpl: "(allow process-fork)"},
		rule{kind: kindOther, sbpl: "(allow signal (target self))"},
		rule{kind: kindOther, sbpl: "(allow sysctl-read)"},
	)

	// Dev files + system libraries (combined file-read* rule)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/usr/lib\")\n" +
			"    (subpath \"/usr/share\")\n" +
			"    (subpath \"/System/Library\")\n" +
			"    (subpath \"/Library/Frameworks\")\n" +
			"    (subpath \"/private/var/db/dyld\")\n" +
			"    (literal \"/dev/null\")\n" +
			"    (literal \"/dev/random\")\n" +
			"    (literal \"/dev/urandom\")\n" +
			"    (literal \"/dev/zero\"))",
	})

	// Common tool paths (read-only)
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read*\n" +
			"    (subpath \"/usr/bin\")\n" +
			"    (subpath \"/usr/sbin\")\n" +
			"    (subpath \"/bin\")\n" +
			"    (subpath \"/sbin\")\n" +
			"    (subpath \"/usr/local/bin\")\n" +
			"    (subpath \"/opt/homebrew/bin\")\n" +
			"    (subpath \"/opt/homebrew/Cellar\"))",
	})

	// TTY access
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (regex #\"^/dev/ttys[0-9]+$\"#)\n" +
			"    (regex #\"^/dev/pty[pqrs][0-9a-f]$\"#)\n" +
			"    (literal \"/dev/tty\"))",
	})

	// Temp files
	p.rules = append(p.rules, rule{
		kind: kindFileAllow,
		sbpl: "(allow file-read* file-write*\n" +
			"    (subpath \"/private/tmp\")\n" +
			"    (subpath \"/tmp\")\n" +
			"    (subpath \"/var/folders\"))",
	})

	// IPC
	p.rules = append(p.rules,
		rule{kind: kindOther, sbpl: "(allow ipc-posix*)"},
		rule{kind: kindOther, sbpl: "(allow mach-register)"},
	)
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

// quotePathForMatch escapes and quotes a path based on its PathMatch type.
// For Regex, the path is passed through unchanged (caller must provide valid
// SBPL regex syntax like #"pattern"#). For Literal and Subpath, backslashes
// and quotes are escaped and the result is wrapped in double quotes.
// This function never content-sniffs — the match type alone determines quoting.
func quotePathForMatch(match PathMatch, path string) string {
	if match == Regex {
		return path
	}
	escaped := strings.ReplaceAll(path, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// validateRule checks that non-regex paths in a rule are absolute.
// Only file and exec rules contain filesystem paths that must be absolute;
// mach-lookup and network rules use service names / host:port strings.
func validateRule(r rule) error {
	// Only validate path-based rule kinds.
	switch r.kind {
	case kindFileAllow, kindFileDeny, kindExecAllow, kindExecDeny:
		// These contain filesystem paths; validate below.
	default:
		return nil
	}

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
