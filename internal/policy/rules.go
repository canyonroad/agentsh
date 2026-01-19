package policy

import "fmt"

// ContextConfig defines depth constraints for rule matching.
// It enables depth-aware policy rules - allowing different policies for
// "direct" (user-typed, depth 0) vs "nested" (script-spawned, depth 1+) commands.
type ContextConfig struct {
	MinDepth int `yaml:"min_depth"`
	MaxDepth int `yaml:"max_depth"` // -1 means unlimited
}

// UnmarshalYAML handles both array syntax [direct, nested] and object syntax.
func (c *ContextConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try array syntax first: [direct], [nested], [direct, nested]
	var arr []string
	if err := unmarshal(&arr); err == nil {
		return c.parseArray(arr)
	}

	// Try object syntax: min_depth, max_depth
	type raw struct {
		MinDepth int `yaml:"min_depth"`
		MaxDepth int `yaml:"max_depth"`
	}
	var r raw
	if err := unmarshal(&r); err != nil {
		return err
	}
	c.MinDepth = r.MinDepth
	c.MaxDepth = r.MaxDepth
	return nil
}

func (c *ContextConfig) parseArray(arr []string) error {
	hasDirect := false
	hasNested := false
	for _, v := range arr {
		switch v {
		case "direct":
			hasDirect = true
		case "nested":
			hasNested = true
		default:
			return fmt.Errorf("unknown context value: %s", v)
		}
	}

	if hasDirect && hasNested {
		// Both = all depths
		c.MinDepth = 0
		c.MaxDepth = -1
	} else if hasDirect {
		c.MinDepth = 0
		c.MaxDepth = 0
	} else if hasNested {
		c.MinDepth = 1
		c.MaxDepth = -1
	}
	return nil
}

// DefaultContext returns a context matching all depths.
func DefaultContext() ContextConfig {
	return ContextConfig{MinDepth: 0, MaxDepth: -1}
}

// MatchesDepth returns true if depth falls within the configured range.
func (c *ContextConfig) MatchesDepth(depth int) bool {
	if depth < c.MinDepth {
		return false
	}
	if c.MaxDepth >= 0 && depth > c.MaxDepth {
		return false
	}
	return true
}
