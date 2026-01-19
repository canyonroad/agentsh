package ancestry

import (
	"strings"
	"sync"

	"github.com/agentsh/agentsh/internal/policy/pattern"
)

// Classifier determines the ProcessClass for process names.
type Classifier struct {
	mu       sync.RWMutex
	registry *pattern.ClassRegistry

	// Custom classification rules (checked first)
	customRules map[string]ProcessClass
}

// NewClassifier creates a new process classifier.
func NewClassifier() *Classifier {
	return &Classifier{
		registry:    pattern.NewClassRegistry(),
		customRules: make(map[string]ProcessClass),
	}
}

// NewClassifierWithRegistry creates a classifier with a custom class registry.
func NewClassifierWithRegistry(registry *pattern.ClassRegistry) *Classifier {
	return &Classifier{
		registry:    registry,
		customRules: make(map[string]ProcessClass),
	}
}

// AddCustomRule adds a custom classification rule.
// Custom rules take precedence over built-in class matching.
func (c *Classifier) AddCustomRule(commPattern string, class ProcessClass) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customRules[commPattern] = class
}

// RemoveCustomRule removes a custom classification rule.
func (c *Classifier) RemoveCustomRule(commPattern string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.customRules, commPattern)
}

// Classify determines the ProcessClass for a process name.
func (c *Classifier) Classify(comm string) ProcessClass {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check custom rules first (exact match)
	if class, ok := c.customRules[comm]; ok {
		return class
	}

	// Check custom rules with pattern matching
	for commPattern, class := range c.customRules {
		if pattern.IsBuiltinClass(commPattern) {
			continue // Skip class references in custom rules for now
		}
		p, err := pattern.Compile(commPattern)
		if err != nil {
			continue
		}
		if p.Match(comm) {
			return class
		}
	}

	// Check built-in classes
	if c.matchesClass("shell", comm) {
		return ClassShell
	}
	if c.matchesClass("editor", comm) {
		return ClassEditor
	}
	if c.matchesClass("agent", comm) {
		return ClassAgent
	}
	if c.matchesClass("build", comm) {
		return ClassBuildTool
	}
	if c.matchesClass("language-server", comm) {
		return ClassLanguageServer
	}
	if c.matchesClass("runtime", comm) {
		return ClassLanguageRuntime
	}

	return ClassUnknown
}

// matchesClass checks if comm matches any pattern in a class.
func (c *Classifier) matchesClass(className, comm string) bool {
	match, err := c.registry.Matches(className, comm)
	if err != nil {
		return false
	}
	return match
}

// ClassifyChain classifies each process in a via chain.
func (c *Classifier) ClassifyChain(via []string) []ProcessClass {
	classes := make([]ProcessClass, len(via))
	for i, comm := range via {
		classes[i] = c.Classify(comm)
	}
	return classes
}

// ClassifyProcess is a convenience function using a default classifier.
func ClassifyProcess(comm string) ProcessClass {
	return DefaultClassifier.Classify(comm)
}

// ClassifyChain is a convenience function using a default classifier.
func ClassifyChainDefault(via []string) []ProcessClass {
	return DefaultClassifier.ClassifyChain(via)
}

// DefaultClassifier is a global classifier instance.
var DefaultClassifier = NewClassifier()

// ChainAnalysis provides analysis of a taint's via chain.
type ChainAnalysis struct {
	Via        []string       // Process names in chain
	ViaClasses []ProcessClass // Classifications of each process

	// Computed properties
	HasShell          bool // Contains a shell process
	HasEditor         bool // Contains an editor process
	HasAgent          bool // Contains an agent process
	HasLanguageServer bool // Contains a language server

	ConsecutiveShells int // Count of consecutive shell processes
	ShellLaundering   bool // Detected shell laundering pattern

	// First occurrences (indices, -1 if not found)
	FirstShellIndex  int
	FirstEditorIndex int
	FirstAgentIndex  int
}

// AnalyzeChain performs comprehensive analysis of a via chain.
func AnalyzeChain(via []string, viaClasses []ProcessClass) *ChainAnalysis {
	analysis := &ChainAnalysis{
		Via:              via,
		ViaClasses:       viaClasses,
		FirstShellIndex:  -1,
		FirstEditorIndex: -1,
		FirstAgentIndex:  -1,
	}

	consecutiveShells := 0
	maxConsecutiveShells := 0

	for i, class := range viaClasses {
		switch class {
		case ClassShell:
			analysis.HasShell = true
			if analysis.FirstShellIndex == -1 {
				analysis.FirstShellIndex = i
			}
			consecutiveShells++
			if consecutiveShells > maxConsecutiveShells {
				maxConsecutiveShells = consecutiveShells
			}
		case ClassEditor:
			analysis.HasEditor = true
			if analysis.FirstEditorIndex == -1 {
				analysis.FirstEditorIndex = i
			}
			consecutiveShells = 0
		case ClassAgent:
			analysis.HasAgent = true
			if analysis.FirstAgentIndex == -1 {
				analysis.FirstAgentIndex = i
			}
			consecutiveShells = 0
		case ClassLanguageServer:
			analysis.HasLanguageServer = true
			consecutiveShells = 0
		default:
			consecutiveShells = 0
		}
	}

	analysis.ConsecutiveShells = maxConsecutiveShells
	// Shell laundering: 3+ consecutive shells suggest an attempt to escape taint
	analysis.ShellLaundering = maxConsecutiveShells >= 3

	return analysis
}

// AnalyzeTaint performs chain analysis on a ProcessTaint.
func AnalyzeTaint(taint *ProcessTaint) *ChainAnalysis {
	if taint == nil {
		return &ChainAnalysis{
			FirstShellIndex:  -1,
			FirstEditorIndex: -1,
			FirstAgentIndex:  -1,
		}
	}
	return AnalyzeChain(taint.Via, taint.ViaClasses)
}

// IsLikelyUserTerminal checks if the chain suggests a user-opened terminal.
// Pattern: Editor spawns shell as first child (depth 1, via[0] is shell).
func IsLikelyUserTerminal(taint *ProcessTaint) bool {
	if taint == nil || taint.Depth != 1 || len(taint.ViaClasses) != 1 {
		return false
	}
	return taint.ViaClasses[0] == ClassShell
}

// IsLikelyEditorFeature checks if the chain suggests an editor feature.
// Pattern: Contains a language server or build tool.
func IsLikelyEditorFeature(taint *ProcessTaint) bool {
	if taint == nil {
		return false
	}
	for _, class := range taint.ViaClasses {
		if class == ClassLanguageServer || class == ClassBuildTool {
			return true
		}
	}
	return false
}

// ChainContainsClass checks if any process in the chain has a specific class.
func ChainContainsClass(classes []ProcessClass, target ProcessClass) bool {
	for _, c := range classes {
		if c == target {
			return true
		}
	}
	return false
}

// ChainContainsComm checks if any process in the chain matches a name pattern.
func ChainContainsComm(via []string, patterns []string) bool {
	for _, comm := range via {
		for _, p := range patterns {
			// Try exact match first
			if comm == p {
				return true
			}
			// Try pattern match
			compiled, err := pattern.Compile(p)
			if err != nil {
				continue
			}
			if compiled.Match(comm) {
				return true
			}
		}
	}
	return false
}

// ChainMatchesPattern checks if any via entry matches a pattern.
func ChainMatchesPattern(via []string, p *pattern.Pattern, resolver func(string) ([]string, error)) bool {
	for _, comm := range via {
		match, _ := p.MatchWithResolver(comm, resolver)
		if match {
			return true
		}
	}
	return false
}

// CountConsecutive counts the maximum consecutive occurrences of a class.
func CountConsecutive(classes []ProcessClass, target ProcessClass) int {
	maxCount := 0
	currentCount := 0

	for _, c := range classes {
		if c == target {
			currentCount++
			if currentCount > maxCount {
				maxCount = currentCount
			}
		} else {
			currentCount = 0
		}
	}

	return maxCount
}

// CountConsecutiveComm counts consecutive occurrences of matching process names.
func CountConsecutiveComm(via []string, patterns []string) int {
	maxCount := 0
	currentCount := 0

	for _, comm := range via {
		matches := false
		for _, p := range patterns {
			if comm == p || strings.Contains(comm, p) {
				matches = true
				break
			}
		}

		if matches {
			currentCount++
			if currentCount > maxCount {
				maxCount = currentCount
			}
		} else {
			currentCount = 0
		}
	}

	return maxCount
}
