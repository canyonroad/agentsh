//go:build windows

package signal

// TargetType identifies the category of signal target.
type TargetType string

const (
	TargetSelf        TargetType = "self"
	TargetChildren    TargetType = "children"
	TargetDescendants TargetType = "descendants"
	TargetSiblings    TargetType = "siblings"
	TargetSession     TargetType = "session"
	TargetParent      TargetType = "parent"
	TargetExternal    TargetType = "external"
	TargetSystem      TargetType = "system"
	TargetUser        TargetType = "user"
	TargetProcess     TargetType = "process"
	TargetPIDRange    TargetType = "pid_range"
)

// TargetSpec defines the target of a signal rule from policy YAML.
type TargetSpec struct {
	Type    string `yaml:"type"`
	Pattern string `yaml:"pattern,omitempty"`
	Min     int    `yaml:"min,omitempty"`
	Max     int    `yaml:"max,omitempty"`
}

// TargetContext provides context about the signal target for policy evaluation.
type TargetContext struct {
	Type        TargetType
	TargetPID   int
	TargetUID   int
	ProcessName string
	InSession   bool
}

// ParseTarget parses a target specification.
func ParseTarget(spec TargetSpec) (*ParsedTarget, error) {
	return nil, ErrSignalUnsupported
}

// ParsedTarget is a validated and compiled target specification.
type ParsedTarget struct {
	Type TargetType
}
