// Package ancestry provides process ancestry tracking and taint propagation
// for parent-conditional policy enforcement.
package ancestry

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/policy/pattern"
)

// DetectionSignal represents a signal source for agent detection.
type DetectionSignal string

const (
	// SignalUserDeclared indicates user declared this process as an agent in config.
	SignalUserDeclared DetectionSignal = "user_declared"
	// SignalSelfRegistered indicates the process self-registered as an agent.
	SignalSelfRegistered DetectionSignal = "self_registered"
	// SignalEnvMarker indicates detection via environment variable pattern.
	SignalEnvMarker DetectionSignal = "env_marker"
	// SignalArgPattern indicates detection via command argument pattern.
	SignalArgPattern DetectionSignal = "arg_pattern"
	// SignalProcessPattern indicates detection via process name pattern.
	SignalProcessPattern DetectionSignal = "process_pattern"
	// SignalBehavioral indicates detection via behavioral analysis.
	SignalBehavioral DetectionSignal = "behavioral"
)

// SignalConfidence maps detection signals to their base confidence scores.
var SignalConfidence = map[DetectionSignal]float64{
	SignalUserDeclared:   1.0, // 100% - explicitly configured
	SignalSelfRegistered: 1.0, // 100% - process declared itself
	SignalEnvMarker:      0.9, // 90% - strong indicator
	SignalArgPattern:     0.9, // 90% - strong indicator
	SignalProcessPattern: 0.8, // 80% - good indicator
	SignalBehavioral:     0.6, // 60% - heuristic
}

// AgentDetectionResult contains the result of agent detection analysis.
type AgentDetectionResult struct {
	IsAgent    bool              // Overall determination
	Confidence float64           // Confidence score (0.0-1.0)
	Signals    []DetectionSignal // Which signals triggered
	Details    map[string]string // Additional context per signal
}

// AgentSignatures defines signature patterns for agent detection.
type AgentSignatures struct {
	// EnvMarkers are environment variable patterns that indicate an agent.
	// Examples: "CLAUDE_AGENT=*", "COPILOT_AGENT_MODE=*", "AIDER_*"
	EnvMarkers []string `yaml:"env_markers,omitempty"`

	// ArgPatterns are command argument patterns that indicate an agent.
	// Examples: "--agent-mode", "--autonomous", "run-agent"
	ArgPatterns []string `yaml:"arg_patterns,omitempty"`

	// ProcessPatterns are process name patterns that indicate an agent.
	// Examples: "*claude*agent*", "*copilot*agent*", "aider"
	ProcessPatterns []string `yaml:"process_patterns,omitempty"`
}

// DefaultAgentSignatures returns the default agent detection signatures.
func DefaultAgentSignatures() AgentSignatures {
	return AgentSignatures{
		EnvMarkers: []string{
			"CLAUDE_AGENT=*",
			"COPILOT_AGENT_MODE=*",
			"AIDER_*",
			"AI_AGENT=*",
			"AGENT_MODE=*",
		},
		ArgPatterns: []string{
			"--agent-mode",
			"--agent",
			"--autonomous",
			"run-agent",
			"agent-run",
		},
		ProcessPatterns: []string{
			"*claude*agent*",
			"*copilot*agent*",
			"aider",
			"*-agent",
			"*_agent",
		},
	}
}

// compiledSignatures holds pre-compiled patterns for efficient matching.
type compiledSignatures struct {
	envMarkers      []*pattern.Pattern
	argPatterns     []*pattern.Pattern
	processPatterns []*pattern.Pattern
}

// AgentDetector detects agent processes using various signals.
type AgentDetector struct {
	mu         sync.RWMutex
	signatures compiledSignatures
	registry   *AgentRegistry
	behavior   *BehaviorDetector

	// Threshold for considering a process an agent
	confidenceThreshold float64
}

// AgentDetectorConfig configures the AgentDetector.
type AgentDetectorConfig struct {
	Signatures          AgentSignatures
	ConfidenceThreshold float64       // Minimum confidence to classify as agent (default: 0.5)
	EnableBehavioral    bool          // Enable behavioral detection (optional)
	BehavioralWindow    time.Duration // Window for behavioral analysis (default: 1 minute)
}

// DefaultAgentDetectorConfig returns default detector configuration.
func DefaultAgentDetectorConfig() AgentDetectorConfig {
	return AgentDetectorConfig{
		Signatures:          DefaultAgentSignatures(),
		ConfidenceThreshold: 0.5,
		EnableBehavioral:    false,
		BehavioralWindow:    time.Minute,
	}
}

// NewAgentDetector creates a new agent detector with the given configuration.
func NewAgentDetector(cfg AgentDetectorConfig) (*AgentDetector, error) {
	d := &AgentDetector{
		confidenceThreshold: cfg.ConfidenceThreshold,
		registry:            NewAgentRegistry(),
	}

	if d.confidenceThreshold <= 0 {
		d.confidenceThreshold = 0.5
	}

	// Compile signatures
	if err := d.compileSignatures(cfg.Signatures); err != nil {
		return nil, err
	}

	// Initialize behavioral detector if enabled
	if cfg.EnableBehavioral {
		d.behavior = NewBehaviorDetector(BehaviorDetectorConfig{
			Window: cfg.BehavioralWindow,
		})
	}

	return d, nil
}

// compileSignatures compiles the signature patterns.
func (d *AgentDetector) compileSignatures(sigs AgentSignatures) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Compile env markers
	for _, p := range sigs.EnvMarkers {
		compiled, err := pattern.Compile(p)
		if err != nil {
			return err
		}
		d.signatures.envMarkers = append(d.signatures.envMarkers, compiled)
	}

	// Compile arg patterns
	for _, p := range sigs.ArgPatterns {
		compiled, err := pattern.Compile(p)
		if err != nil {
			return err
		}
		d.signatures.argPatterns = append(d.signatures.argPatterns, compiled)
	}

	// Compile process patterns
	for _, p := range sigs.ProcessPatterns {
		compiled, err := pattern.Compile(p)
		if err != nil {
			return err
		}
		d.signatures.processPatterns = append(d.signatures.processPatterns, compiled)
	}

	return nil
}

// DetectContext provides information for agent detection.
type DetectContext struct {
	PID         int
	Comm        string
	Args        []string
	Env         map[string]string
	ExePath     string
	UserMarkers []string // Processes user declared as agents in config
}

// Detect analyzes a process and returns detection result.
func (d *AgentDetector) Detect(ctx *DetectContext) AgentDetectionResult {
	result := AgentDetectionResult{
		Details: make(map[string]string),
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// Check user declaration first (highest confidence)
	if d.checkUserDeclared(ctx, &result) {
		return d.finalizeResult(&result)
	}

	// Check self-registration
	if d.checkSelfRegistration(ctx, &result) {
		return d.finalizeResult(&result)
	}

	// Check environment markers
	d.checkEnvMarkers(ctx, &result)

	// Check argument patterns
	d.checkArgPatterns(ctx, &result)

	// Check process patterns
	d.checkProcessPatterns(ctx, &result)

	// Check behavioral signals (if enabled)
	if d.behavior != nil {
		d.checkBehavioral(ctx, &result)
	}

	return d.finalizeResult(&result)
}

// checkUserDeclared checks if the process is declared as an agent by user config.
func (d *AgentDetector) checkUserDeclared(ctx *DetectContext, result *AgentDetectionResult) bool {
	for _, marker := range ctx.UserMarkers {
		// Check if comm matches
		if strings.EqualFold(marker, ctx.Comm) {
			result.Signals = append(result.Signals, SignalUserDeclared)
			result.Details["user_declared"] = marker
			return true
		}
		// Check if exe path matches
		if marker == ctx.ExePath || strings.HasSuffix(ctx.ExePath, "/"+marker) {
			result.Signals = append(result.Signals, SignalUserDeclared)
			result.Details["user_declared"] = marker
			return true
		}
	}
	return false
}

// checkSelfRegistration checks if the process self-registered as an agent.
func (d *AgentDetector) checkSelfRegistration(ctx *DetectContext, result *AgentDetectionResult) bool {
	// Check environment variable for self-registration
	if agentID := ctx.Env["AGENTSH_AGENT_ID"]; agentID != "" {
		result.Signals = append(result.Signals, SignalSelfRegistered)
		result.Details["self_registered"] = agentID
		return true
	}

	// Check registry for self-registration
	if d.registry.IsRegistered(ctx.PID) {
		result.Signals = append(result.Signals, SignalSelfRegistered)
		result.Details["self_registered"] = "registry"
		return true
	}

	return false
}

// checkEnvMarkers checks environment variables for agent markers.
func (d *AgentDetector) checkEnvMarkers(ctx *DetectContext, result *AgentDetectionResult) {
	if ctx.Env == nil {
		return
	}

	for _, p := range d.signatures.envMarkers {
		for key, value := range ctx.Env {
			// Match against "KEY=VALUE" format or just key
			envStr := key + "=" + value
			if p.Match(envStr) || p.Match(key) {
				result.Signals = append(result.Signals, SignalEnvMarker)
				result.Details["env_marker"] = envStr
				return // Only count once
			}
		}
	}
}

// checkArgPatterns checks command arguments for agent patterns.
func (d *AgentDetector) checkArgPatterns(ctx *DetectContext, result *AgentDetectionResult) {
	for _, p := range d.signatures.argPatterns {
		for _, arg := range ctx.Args {
			if p.Match(arg) {
				result.Signals = append(result.Signals, SignalArgPattern)
				result.Details["arg_pattern"] = arg
				return // Only count once
			}
		}
		// Also check the full command line
		fullCmd := strings.Join(ctx.Args, " ")
		if p.Match(fullCmd) {
			result.Signals = append(result.Signals, SignalArgPattern)
			result.Details["arg_pattern"] = fullCmd
			return
		}
	}
}

// checkProcessPatterns checks process name for agent patterns.
func (d *AgentDetector) checkProcessPatterns(ctx *DetectContext, result *AgentDetectionResult) {
	for _, p := range d.signatures.processPatterns {
		// Check comm
		if p.Match(ctx.Comm) || p.Match(strings.ToLower(ctx.Comm)) {
			result.Signals = append(result.Signals, SignalProcessPattern)
			result.Details["process_pattern"] = ctx.Comm
			return
		}
		// Check exe path basename
		if ctx.ExePath != "" {
			base := filepath.Base(ctx.ExePath)
			if p.Match(base) || p.Match(strings.ToLower(base)) {
				result.Signals = append(result.Signals, SignalProcessPattern)
				result.Details["process_pattern"] = base
				return
			}
		}
	}
}

// checkBehavioral checks for behavioral signals of agent activity.
func (d *AgentDetector) checkBehavioral(ctx *DetectContext, result *AgentDetectionResult) {
	if d.behavior == nil {
		return
	}

	score := d.behavior.GetScore(ctx.PID)
	if score > 0.5 {
		result.Signals = append(result.Signals, SignalBehavioral)
		result.Details["behavioral"] = "high_activity"
	}
}

// finalizeResult calculates the final confidence and determination.
func (d *AgentDetector) finalizeResult(result *AgentDetectionResult) AgentDetectionResult {
	if len(result.Signals) == 0 {
		result.IsAgent = false
		result.Confidence = 0.0
		return *result
	}

	// Calculate combined confidence using noisy-or
	// P(agent) = 1 - ∏(1 - P_i) for independent signals
	notAgent := 1.0
	for _, signal := range result.Signals {
		if conf, ok := SignalConfidence[signal]; ok {
			notAgent *= (1 - conf)
		}
	}
	result.Confidence = 1 - notAgent

	// Determine if this is an agent based on threshold
	result.IsAgent = result.Confidence >= d.confidenceThreshold

	return *result
}

// Registry returns the agent registry.
func (d *AgentDetector) Registry() *AgentRegistry {
	return d.registry
}

// RecordExec records an execution for behavioral analysis.
func (d *AgentDetector) RecordExec(pid int) {
	if d.behavior != nil {
		d.behavior.RecordExec(pid)
	}
}

// RecordNetworkAccess records network access for behavioral analysis.
func (d *AgentDetector) RecordNetworkAccess(pid int, domain string) {
	if d.behavior != nil {
		d.behavior.RecordNetworkAccess(pid, domain)
	}
}

// AgentRegistry handles self-registration of agent processes.
type AgentRegistry struct {
	mu         sync.RWMutex
	registered map[int]RegistrationInfo
}

// RegistrationInfo contains information about a registered agent.
type RegistrationInfo struct {
	AgentID      string
	RegisteredAt time.Time
	Method       string // "env", "file", "api"
}

// NewAgentRegistry creates a new agent registry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		registered: make(map[int]RegistrationInfo),
	}
}

// Register registers a process as an agent.
func (r *AgentRegistry) Register(pid int, agentID string, method string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registered[pid] = RegistrationInfo{
		AgentID:      agentID,
		RegisteredAt: time.Now(),
		Method:       method,
	}
}

// Unregister removes a process from the registry.
func (r *AgentRegistry) Unregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.registered, pid)
}

// IsRegistered checks if a process is registered as an agent.
func (r *AgentRegistry) IsRegistered(pid int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.registered[pid]
	return ok
}

// GetInfo returns registration info for a process.
func (r *AgentRegistry) GetInfo(pid int) (RegistrationInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	info, ok := r.registered[pid]
	return info, ok
}

// CheckMarkerFile checks for an agent marker file.
// Agents can create ~/.agentsh/agent-<pid> to self-register.
func (r *AgentRegistry) CheckMarkerFile(pid int) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	markerPath := filepath.Join(home, ".agentsh", "agent-"+string(rune(pid)))
	_, err = os.Stat(markerPath)
	return err == nil
}

// BehaviorDetector detects agent behavior through heuristics.
type BehaviorDetector struct {
	mu         sync.RWMutex
	execCounts map[int][]time.Time    // PID -> exec timestamps
	netAccess  map[int][]NetworkEvent // PID -> network access events
	window     time.Duration

	// LLM API domains that suggest agent activity
	llmDomains map[string]bool
}

// NetworkEvent records a network access event.
type NetworkEvent struct {
	Time   time.Time
	Domain string
}

// BehaviorDetectorConfig configures the behavioral detector.
type BehaviorDetectorConfig struct {
	Window time.Duration // Time window for analysis (default: 1 minute)
}

// NewBehaviorDetector creates a new behavioral detector.
func NewBehaviorDetector(cfg BehaviorDetectorConfig) *BehaviorDetector {
	window := cfg.Window
	if window <= 0 {
		window = time.Minute
	}

	return &BehaviorDetector{
		execCounts: make(map[int][]time.Time),
		netAccess:  make(map[int][]NetworkEvent),
		window:     window,
		llmDomains: map[string]bool{
			"api.anthropic.com":    true,
			"api.openai.com":       true,
			"generativelanguage.googleapis.com": true,
			"claude.ai":            true,
			"chat.openai.com":      true,
			"api.cohere.ai":        true,
		},
	}
}

// RecordExec records an execution event for a process.
func (d *BehaviorDetector) RecordExec(pid int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.execCounts[pid] = append(d.execCounts[pid], now)
	d.cleanup(pid)
}

// RecordNetworkAccess records a network access event.
func (d *BehaviorDetector) RecordNetworkAccess(pid int, domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.netAccess[pid] = append(d.netAccess[pid], NetworkEvent{
		Time:   now,
		Domain: domain,
	})
	d.cleanup(pid)
}

// cleanup removes events outside the time window.
func (d *BehaviorDetector) cleanup(pid int) {
	cutoff := time.Now().Add(-d.window)

	// Cleanup exec counts
	if execs, ok := d.execCounts[pid]; ok {
		filtered := make([]time.Time, 0)
		for _, t := range execs {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) > 0 {
			d.execCounts[pid] = filtered
		} else {
			delete(d.execCounts, pid)
		}
	}

	// Cleanup network events
	if events, ok := d.netAccess[pid]; ok {
		filtered := make([]NetworkEvent, 0)
		for _, e := range events {
			if e.Time.After(cutoff) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) > 0 {
			d.netAccess[pid] = filtered
		} else {
			delete(d.netAccess, pid)
		}
	}
}

// GetScore calculates a behavioral score for a process.
// Returns a value between 0.0 and 1.0.
func (d *BehaviorDetector) GetScore(pid int) float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	score := 0.0

	// High exec rate (>10/min = 0.3)
	if execs, ok := d.execCounts[pid]; ok {
		rate := float64(len(execs)) / d.window.Minutes()
		if rate > 10 {
			score += 0.3
		}
	}

	// Contacts LLM APIs (0.5)
	if events, ok := d.netAccess[pid]; ok {
		for _, e := range events {
			if d.llmDomains[e.Domain] {
				score += 0.5
				break
			}
		}
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// Clear removes all recorded events for a process.
func (d *BehaviorDetector) Clear(pid int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.execCounts, pid)
	delete(d.netAccess, pid)
}
