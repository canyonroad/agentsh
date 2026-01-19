// Package pattern provides pattern matching for process identification.
// Supports glob patterns (default), regex patterns (re: prefix), and
// built-in class expansion (@ prefix).
package pattern

import (
	"context"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/glob"
)

// PatternType indicates the type of pattern.
type PatternType int

const (
	// PatternTypeGlob is the default glob pattern (e.g., "cursor*").
	PatternTypeGlob PatternType = iota
	// PatternTypeRegex is a regex pattern (prefixed with "re:").
	PatternTypeRegex
	// PatternTypeClass is a built-in class reference (prefixed with "@").
	PatternTypeClass
	// PatternTypeLiteral is an exact string match.
	PatternTypeLiteral
)

// String returns the string representation of a PatternType.
func (t PatternType) String() string {
	switch t {
	case PatternTypeGlob:
		return "glob"
	case PatternTypeRegex:
		return "regex"
	case PatternTypeClass:
		return "class"
	case PatternTypeLiteral:
		return "literal"
	default:
		return "unknown"
	}
}

// Pattern represents a compiled pattern for matching strings.
type Pattern struct {
	Raw     string      // Original pattern string
	Type    PatternType // Type of pattern
	compiled interface{} // *regexp.Regexp or glob.Glob
	class   string       // For class patterns, the class name without @
}

// CompileOptions configures pattern compilation.
type CompileOptions struct {
	// ClassResolver resolves class names to patterns.
	// If nil, class patterns will return an error.
	ClassResolver func(class string) ([]string, error)

	// MaxRegexComplexity limits regex complexity to prevent ReDoS.
	// 0 means use default (1000).
	MaxRegexComplexity int

	// CaseInsensitive makes matching case-insensitive.
	CaseInsensitive bool
}

// DefaultCompileOptions returns default compilation options.
func DefaultCompileOptions() CompileOptions {
	return CompileOptions{
		MaxRegexComplexity: 1000,
		CaseInsensitive:    false,
	}
}

// Compile compiles a pattern string into a Pattern.
// Pattern types:
//   - "re:..." - Regex pattern
//   - "@..." - Built-in class reference
//   - "*", "?", "[...]" - Glob pattern
//   - Otherwise - Literal match
func Compile(s string) (*Pattern, error) {
	return CompileWithOptions(s, DefaultCompileOptions())
}

// CompileWithOptions compiles a pattern with custom options.
func CompileWithOptions(s string, opts CompileOptions) (*Pattern, error) {
	if s == "" {
		return nil, fmt.Errorf("empty pattern")
	}

	// Check for regex prefix
	if strings.HasPrefix(s, "re:") {
		return compileRegex(s, opts)
	}

	// Check for class prefix
	if strings.HasPrefix(s, "@") {
		return compileClass(s, opts)
	}

	// Check if it's a glob pattern (contains *, ?, or [...])
	if isGlobPattern(s) {
		return compileGlob(s, opts)
	}

	// Literal match
	return &Pattern{
		Raw:      s,
		Type:     PatternTypeLiteral,
		compiled: s,
	}, nil
}

func compileRegex(s string, opts CompileOptions) (*Pattern, error) {
	regexStr := strings.TrimPrefix(s, "re:")
	if regexStr == "" {
		return nil, fmt.Errorf("empty regex pattern")
	}

	// Check regex complexity to prevent ReDoS
	if err := checkRegexComplexity(regexStr, opts.MaxRegexComplexity); err != nil {
		return nil, fmt.Errorf("regex complexity check failed: %w", err)
	}

	// Compile regex
	flags := ""
	if opts.CaseInsensitive {
		flags = "(?i)"
	}

	re, err := regexp.Compile(flags + regexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	return &Pattern{
		Raw:      s,
		Type:     PatternTypeRegex,
		compiled: re,
	}, nil
}

func compileClass(s string, opts CompileOptions) (*Pattern, error) {
	className := strings.TrimPrefix(s, "@")
	if className == "" {
		return nil, fmt.Errorf("empty class name")
	}

	// Class patterns are resolved at match time, not compile time.
	// This allows lazy resolution and avoids circular dependencies.
	return &Pattern{
		Raw:   s,
		Type:  PatternTypeClass,
		class: className,
	}, nil
}

func compileGlob(s string, opts CompileOptions) (*Pattern, error) {
	var g glob.Glob
	var err error

	if opts.CaseInsensitive {
		g, err = glob.Compile(strings.ToLower(s))
	} else {
		g, err = glob.Compile(s)
	}

	if err != nil {
		return nil, fmt.Errorf("invalid glob pattern: %w", err)
	}

	return &Pattern{
		Raw:      s,
		Type:     PatternTypeGlob,
		compiled: g,
	}, nil
}

// isGlobPattern checks if a string contains glob special characters.
func isGlobPattern(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// checkRegexComplexity analyzes a regex for potential ReDoS vulnerabilities.
// It checks for patterns that could cause exponential backtracking.
func checkRegexComplexity(pattern string, maxComplexity int) error {
	if maxComplexity == 0 {
		maxComplexity = 1000
	}

	// Parse the regex syntax tree
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return fmt.Errorf("failed to parse regex: %w", err)
	}

	// Calculate complexity score
	complexity := calculateComplexity(re)
	if complexity > maxComplexity {
		return fmt.Errorf("regex complexity %d exceeds maximum %d (potential ReDoS)", complexity, maxComplexity)
	}

	return nil
}

// calculateComplexity calculates a complexity score for a regex syntax tree.
// Higher scores indicate more potential for backtracking.
func calculateComplexity(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
		// Unbounded repetition - high complexity
		subComplexity := 0
		for _, sub := range re.Sub {
			subComplexity += calculateComplexity(sub)
		}
		// Nested quantifiers are especially dangerous
		if subComplexity > 1 {
			return subComplexity * 100
		}
		return subComplexity + 10

	case syntax.OpQuest:
		// Optional - moderate complexity
		subComplexity := 0
		for _, sub := range re.Sub {
			subComplexity += calculateComplexity(sub)
		}
		return subComplexity + 2

	case syntax.OpRepeat:
		// Bounded repetition
		subComplexity := 0
		for _, sub := range re.Sub {
			subComplexity += calculateComplexity(sub)
		}
		// Factor in the max repetition count
		maxRep := re.Max
		if maxRep < 0 {
			maxRep = 100 // Unbounded
		}
		return subComplexity * maxRep / 10

	case syntax.OpConcat:
		// Concatenation - sum of sub complexities
		total := 0
		for _, sub := range re.Sub {
			total += calculateComplexity(sub)
		}
		return total

	case syntax.OpAlternate:
		// Alternation - can cause backtracking
		total := 0
		for _, sub := range re.Sub {
			total += calculateComplexity(sub)
		}
		return total * 2

	case syntax.OpCapture:
		// Capture group
		total := 0
		for _, sub := range re.Sub {
			total += calculateComplexity(sub)
		}
		return total + 1

	default:
		// Simple patterns
		return 1
	}
}

// Match checks if the input string matches the pattern.
// For class patterns, a ClassResolver must have been provided at compile time,
// or this will return false.
func (p *Pattern) Match(s string) bool {
	match, _ := p.MatchWithResolver(s, nil)
	return match
}

// MatchWithResolver checks if the input matches, using the resolver for class patterns.
func (p *Pattern) MatchWithResolver(s string, resolver func(string) ([]string, error)) (bool, error) {
	switch p.Type {
	case PatternTypeLiteral:
		return s == p.compiled.(string), nil

	case PatternTypeGlob:
		g := p.compiled.(glob.Glob)
		return g.Match(s), nil

	case PatternTypeRegex:
		re := p.compiled.(*regexp.Regexp)
		return re.MatchString(s), nil

	case PatternTypeClass:
		if resolver == nil {
			return false, fmt.Errorf("no class resolver provided for class pattern @%s", p.class)
		}
		patterns, err := resolver(p.class)
		if err != nil {
			return false, fmt.Errorf("failed to resolve class @%s: %w", p.class, err)
		}
		// Check if input matches any pattern in the class
		for _, pattern := range patterns {
			subPattern, err := Compile(pattern)
			if err != nil {
				continue // Skip invalid patterns
			}
			if subPattern.Match(s) {
				return true, nil
			}
		}
		return false, nil

	default:
		return false, fmt.Errorf("unknown pattern type: %v", p.Type)
	}
}

// MatchWithTimeout checks if the input matches with a timeout.
// This is useful for regex patterns that might take too long.
func (p *Pattern) MatchWithTimeout(s string, timeout time.Duration) (bool, error) {
	return p.MatchWithTimeoutAndResolver(s, timeout, nil)
}

// MatchWithTimeoutAndResolver matches with timeout and class resolver.
func (p *Pattern) MatchWithTimeoutAndResolver(s string, timeout time.Duration, resolver func(string) ([]string, error)) (bool, error) {
	if timeout <= 0 {
		return p.MatchWithResolver(s, resolver)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan struct {
		match bool
		err   error
	}, 1)

	go func() {
		match, err := p.MatchWithResolver(s, resolver)
		select {
		case resultCh <- struct {
			match bool
			err   error
		}{match, err}:
		case <-ctx.Done():
		}
	}()

	select {
	case result := <-resultCh:
		return result.match, result.err
	case <-ctx.Done():
		return false, fmt.Errorf("pattern match timed out after %v", timeout)
	}
}

// String returns the original pattern string.
func (p *Pattern) String() string {
	return p.Raw
}

// PatternSet is a collection of patterns that can be matched together.
type PatternSet struct {
	patterns []*Pattern
	mu       sync.RWMutex
}

// NewPatternSet creates a new pattern set from pattern strings.
func NewPatternSet(patterns []string) (*PatternSet, error) {
	ps := &PatternSet{
		patterns: make([]*Pattern, 0, len(patterns)),
	}

	for _, p := range patterns {
		pattern, err := Compile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern %q: %w", p, err)
		}
		ps.patterns = append(ps.patterns, pattern)
	}

	return ps, nil
}

// MatchAny returns true if any pattern in the set matches the input.
func (ps *PatternSet) MatchAny(s string) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	for _, p := range ps.patterns {
		if p.Match(s) {
			return true
		}
	}
	return false
}

// MatchAnyWithResolver returns true if any pattern matches, using resolver for classes.
func (ps *PatternSet) MatchAnyWithResolver(s string, resolver func(string) ([]string, error)) (bool, error) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	for _, p := range ps.patterns {
		match, err := p.MatchWithResolver(s, resolver)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

// Patterns returns the patterns in the set.
func (ps *PatternSet) Patterns() []*Pattern {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make([]*Pattern, len(ps.patterns))
	copy(result, ps.patterns)
	return result
}

// Len returns the number of patterns in the set.
func (ps *PatternSet) Len() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.patterns)
}
