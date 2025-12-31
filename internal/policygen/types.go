// internal/policygen/types.go
package policygen

import (
	"fmt"
	"time"
)

// Options controls policy generation behavior.
type Options struct {
	Name           string // Policy name (default: generated-<session-id>)
	Threshold      int    // Files in same dir before collapsing to glob
	IncludeBlocked bool   // Include blocked ops as comments
	ArgPatterns    bool   // Generate arg patterns for risky commands
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Threshold:      5,
		IncludeBlocked: true,
		ArgPatterns:    true,
	}
}

// Provenance tracks the source events for a generated rule.
type Provenance struct {
	EventCount  int
	FirstSeen   time.Time
	LastSeen    time.Time
	SamplePaths []string // Up to 3 example paths/domains/commands
	Blocked     bool     // True if this was a blocked operation
	BlockReason string   // Reason if blocked
}

// String returns a human-readable provenance comment.
func (p Provenance) String() string {
	timeRange := ""
	if !p.FirstSeen.IsZero() && !p.LastSeen.IsZero() {
		timeRange = fmt.Sprintf(" (%s - %s)",
			p.FirstSeen.Format("15:04:05"),
			p.LastSeen.Format("15:04:05"))
	}
	return fmt.Sprintf("%d events%s", p.EventCount, timeRange)
}

// GeneratedRule represents a rule with its provenance.
type GeneratedRule struct {
	Name        string
	Description string
	Provenance  Provenance
}

// FileRuleGen extends GeneratedRule for file rules.
type FileRuleGen struct {
	GeneratedRule
	Paths      []string
	Operations []string
	Decision   string
}

// NetworkRuleGen extends GeneratedRule for network rules.
type NetworkRuleGen struct {
	GeneratedRule
	Domains  []string
	Ports    []int
	CIDRs    []string
	Decision string
}

// CommandRuleGen extends GeneratedRule for command rules.
type CommandRuleGen struct {
	GeneratedRule
	Commands    []string
	ArgsPattern string // Regex pattern for risky commands
	Decision    string
	Risky       bool   // If true, this is a risky command
	RiskyReason string // Why it's risky (builtin, network, destructive)
}

// UnixRuleGen extends GeneratedRule for unix socket rules.
type UnixRuleGen struct {
	GeneratedRule
	Paths      []string
	Operations []string
	Decision   string
}

// GeneratedPolicy holds all generated rules.
type GeneratedPolicy struct {
	SessionID   string
	GeneratedAt time.Time
	Duration    time.Duration
	EventCount  int

	FileRules    []FileRuleGen
	NetworkRules []NetworkRuleGen
	CommandRules []CommandRuleGen
	UnixRules    []UnixRuleGen

	// Blocked operations (for comments)
	BlockedFiles    []FileRuleGen
	BlockedNetwork  []NetworkRuleGen
	BlockedCommands []CommandRuleGen
}
