// Package simulation provides testing and simulation modes for agentsh.
package simulation

// ModeConfig defines simulation mode configuration.
type ModeConfig struct {
	// DryRun logs what would happen without enforcing
	DryRun DryRunConfig `json:"dry_run" yaml:"dry_run"`

	// Simulation runs against recorded sessions
	Simulation SimulationConfig `json:"simulation" yaml:"simulation"`

	// Permissive allows all but logs everything
	Permissive PermissiveConfig `json:"permissive" yaml:"permissive"`

	// Strict denies by default
	Strict StrictConfig `json:"strict" yaml:"strict"`
}

// DryRunConfig configures dry-run mode.
type DryRunConfig struct {
	Enabled      bool `json:"enabled" yaml:"enabled"`
	LogDecisions bool `json:"log_decisions" yaml:"log_decisions"`
}

// SimulationConfig configures simulation/replay mode.
type SimulationConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	ReplayFile string `json:"replay_file" yaml:"replay_file"`
}

// PermissiveConfig configures permissive mode.
type PermissiveConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// StrictConfig configures strict mode.
type StrictConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// DefaultModeConfig returns sensible defaults.
func DefaultModeConfig() ModeConfig {
	return ModeConfig{
		DryRun: DryRunConfig{
			Enabled:      false,
			LogDecisions: true,
		},
		Simulation: SimulationConfig{
			Enabled: false,
		},
		Permissive: PermissiveConfig{
			Enabled: false,
		},
		Strict: StrictConfig{
			Enabled: true,
		},
	}
}

// Mode represents the current operational mode.
type Mode string

const (
	ModeNormal     Mode = "normal"
	ModeDryRun     Mode = "dry_run"
	ModeSimulation Mode = "simulation"
	ModePermissive Mode = "permissive"
	ModeStrict     Mode = "strict"
)

// Decision represents a policy decision.
type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionDeny     Decision = "deny"
	DecisionApprove  Decision = "approve"
	DecisionRedirect Decision = "redirect"
	DecisionAudit    Decision = "audit"
)

// ModeManager manages operational modes.
type ModeManager struct {
	config      ModeConfig
	currentMode Mode
	logger      DecisionLogger
}

// DecisionLogger logs decisions in various modes.
type DecisionLogger interface {
	LogDecision(op *Operation, decision Decision, wouldEnforce bool)
}

// Operation represents an operation being evaluated.
type Operation struct {
	Type        string            `json:"type"`
	Path        string            `json:"path,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	Variable    string            `json:"variable,omitempty"`
	ProcessName string            `json:"process_name,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// NewModeManager creates a new mode manager.
func NewModeManager(config ModeConfig, logger DecisionLogger) *ModeManager {
	m := &ModeManager{
		config: config,
		logger: logger,
	}
	m.currentMode = m.detectMode()
	return m
}

// detectMode determines the active mode from config.
func (m *ModeManager) detectMode() Mode {
	if m.config.DryRun.Enabled {
		return ModeDryRun
	}
	if m.config.Simulation.Enabled {
		return ModeSimulation
	}
	if m.config.Permissive.Enabled {
		return ModePermissive
	}
	if m.config.Strict.Enabled {
		return ModeStrict
	}
	return ModeNormal
}

// CurrentMode returns the current operational mode.
func (m *ModeManager) CurrentMode() Mode {
	return m.currentMode
}

// SetMode changes the operational mode.
func (m *ModeManager) SetMode(mode Mode) {
	m.currentMode = mode
}

// ShouldEnforce returns whether decisions should be enforced.
func (m *ModeManager) ShouldEnforce() bool {
	switch m.currentMode {
	case ModeDryRun:
		return false
	case ModePermissive:
		return false
	default:
		return true
	}
}

// ShouldLog returns whether decisions should be logged.
func (m *ModeManager) ShouldLog() bool {
	switch m.currentMode {
	case ModeDryRun:
		return m.config.DryRun.LogDecisions
	case ModePermissive:
		return true
	default:
		return true
	}
}

// DefaultDecision returns the default decision for the current mode.
func (m *ModeManager) DefaultDecision() Decision {
	switch m.currentMode {
	case ModePermissive:
		return DecisionAllow
	case ModeStrict:
		return DecisionDeny
	default:
		return DecisionDeny
	}
}

// ProcessDecision processes a decision based on the current mode.
func (m *ModeManager) ProcessDecision(op *Operation, decision Decision) Decision {
	wouldEnforce := m.ShouldEnforce()

	// Log if needed
	if m.ShouldLog() && m.logger != nil {
		m.logger.LogDecision(op, decision, wouldEnforce)
	}

	// In dry-run and permissive modes, always allow
	if !wouldEnforce {
		return DecisionAllow
	}

	return decision
}

// IsDryRun returns whether dry-run mode is active.
func (m *ModeManager) IsDryRun() bool {
	return m.currentMode == ModeDryRun
}

// IsSimulation returns whether simulation mode is active.
func (m *ModeManager) IsSimulation() bool {
	return m.currentMode == ModeSimulation
}

// IsPermissive returns whether permissive mode is active.
func (m *ModeManager) IsPermissive() bool {
	return m.currentMode == ModePermissive
}

// IsStrict returns whether strict mode is active.
func (m *ModeManager) IsStrict() bool {
	return m.currentMode == ModeStrict
}

// Config returns the current mode configuration.
func (m *ModeManager) Config() ModeConfig {
	return m.config
}
