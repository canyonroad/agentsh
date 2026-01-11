//go:build !windows

// internal/signal/target.go
package signal

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

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
	Pattern string `yaml:"pattern,omitempty"` // For process name matching
	Min     int    `yaml:"min,omitempty"`     // For pid_range
	Max     int    `yaml:"max,omitempty"`     // For pid_range
}

// ParsedTarget is a validated and compiled target specification.
type ParsedTarget struct {
	Type        TargetType
	ProcessGlob glob.Glob // For process name matching
	PIDMin      int
	PIDMax      int
}

// validTargetTypes lists all valid target type strings.
var validTargetTypes = map[string]TargetType{
	"self":        TargetSelf,
	"children":    TargetChildren,
	"descendants": TargetDescendants,
	"siblings":    TargetSiblings,
	"session":     TargetSession,
	"parent":      TargetParent,
	"external":    TargetExternal,
	"system":      TargetSystem,
	"user":        TargetUser,
	"process":     TargetProcess,
	"pid_range":   TargetPIDRange,
}

// ParseTargetSpec validates and compiles a target specification.
func ParseTargetSpec(spec TargetSpec) (*ParsedTarget, error) {
	typeStr := strings.ToLower(strings.TrimSpace(spec.Type))
	targetType, ok := validTargetTypes[typeStr]
	if !ok {
		return nil, fmt.Errorf("invalid target type: %s", spec.Type)
	}

	parsed := &ParsedTarget{
		Type:   targetType,
		PIDMin: spec.Min,
		PIDMax: spec.Max,
	}

	// Compile process pattern if specified
	if targetType == TargetProcess && spec.Pattern != "" {
		g, err := glob.Compile(spec.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid process pattern %q: %w", spec.Pattern, err)
		}
		parsed.ProcessGlob = g
	}

	// Validate pid_range
	if targetType == TargetPIDRange {
		if spec.Min <= 0 || spec.Max <= 0 {
			return nil, fmt.Errorf("pid_range requires positive min and max")
		}
		if spec.Min > spec.Max {
			return nil, fmt.Errorf("pid_range min (%d) > max (%d)", spec.Min, spec.Max)
		}
	}

	return parsed, nil
}

// TargetContext provides information about the signal source and target.
type TargetContext struct {
	SourcePID    int
	TargetPID    int
	TargetCmd    string
	IsChild      bool
	IsDescendant bool
	IsSibling    bool
	IsParent     bool
	InSession    bool
	SameUser     bool
}

// Matches checks if a target PID matches this target specification.
func (t *ParsedTarget) Matches(ctx *TargetContext) bool {
	switch t.Type {
	case TargetSelf:
		return ctx.TargetPID == ctx.SourcePID
	case TargetChildren:
		return ctx.IsChild
	case TargetDescendants:
		return ctx.IsDescendant
	case TargetSiblings:
		return ctx.IsSibling
	case TargetSession:
		return ctx.InSession
	case TargetParent:
		return ctx.IsParent
	case TargetExternal:
		return !ctx.InSession
	case TargetSystem:
		// Match PID 1 (init) and PID 2 (kthreadd, Linux kernel thread parent)
		// Other kernel threads have higher PIDs but are children of PID 2
		return ctx.TargetPID == 1 || ctx.TargetPID == 2
	case TargetUser:
		return ctx.SameUser && !ctx.InSession
	case TargetProcess:
		if t.ProcessGlob == nil {
			return false
		}
		return t.ProcessGlob.Match(ctx.TargetCmd)
	case TargetPIDRange:
		return ctx.TargetPID >= t.PIDMin && ctx.TargetPID <= t.PIDMax
	default:
		return false
	}
}
