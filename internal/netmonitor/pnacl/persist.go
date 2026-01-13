package pnacl

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// FileRulePersister persists rules to a YAML configuration file.
type FileRulePersister struct {
	mu       sync.Mutex
	filePath string
}

// NewFileRulePersister creates a new file-based rule persister.
func NewFileRulePersister(filePath string) *FileRulePersister {
	return &FileRulePersister{
		filePath: filePath,
	}
}

// AddRule adds a rule to the configuration file.
func (p *FileRulePersister) AddRule(processName string, target NetworkTarget, comment string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Load existing config or create new one
	config, err := p.loadOrCreateConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Find or create process config
	var processConfig *ProcessConfig
	for i := range config.Processes {
		if config.Processes[i].Name == processName {
			processConfig = &config.Processes[i]
			break
		}
	}

	if processConfig == nil {
		// Create new process config
		config.Processes = append(config.Processes, ProcessConfig{
			Name: processName,
			Match: ProcessMatchCriteria{
				ProcessName: processName,
			},
			Default: string(DecisionApprove),
			Rules:   []NetworkTarget{},
		})
		processConfig = &config.Processes[len(config.Processes)-1]
	}

	// Check if rule already exists
	if p.ruleExists(processConfig.Rules, target) {
		return nil // Rule already exists, nothing to do
	}

	// Add the new rule at the beginning (highest priority)
	processConfig.Rules = append([]NetworkTarget{target}, processConfig.Rules...)

	// Write config with comment
	return p.writeConfigWithComment(config, processName, comment)
}

// ruleExists checks if an equivalent rule already exists.
func (p *FileRulePersister) ruleExists(rules []NetworkTarget, target NetworkTarget) bool {
	for _, r := range rules {
		if r.Host == target.Host &&
			r.IP == target.IP &&
			r.CIDR == target.CIDR &&
			r.Port == target.Port &&
			r.Protocol == target.Protocol &&
			r.Decision == target.Decision {
			return true
		}
	}
	return false
}

// loadOrCreateConfig loads the existing config or creates a new one.
func (p *FileRulePersister) loadOrCreateConfig() (*Config, error) {
	data, err := os.ReadFile(p.filePath)
	if os.IsNotExist(err) {
		// Create new config
		return &Config{
			Default:   string(DecisionApprove),
			Processes: []ProcessConfig{},
		}, nil
	}
	if err != nil {
		return nil, err
	}

	return ParseConfig(data)
}

// writeConfigWithComment writes the config to file with a comment for the new rule.
func (p *FileRulePersister) writeConfigWithComment(config *Config, processName, comment string) error {
	// Ensure directory exists
	dir := filepath.Dir(p.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Marshal to YAML
	var buf bytes.Buffer

	// Write header comment
	buf.WriteString("# PNACL Configuration\n")
	buf.WriteString("# Auto-generated rules are added at the top of each process's rules list\n")
	buf.WriteString("# Manual rules below auto-generated rules will be evaluated after\n\n")

	// Marshal the config
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	encoder.Close()

	// Read the output and inject comment before the new rule
	output := buf.String()
	if comment != "" {
		// Find the process section and inject comment before first rule
		output = p.injectComment(output, processName, comment)
	}

	// Write to file
	if err := os.WriteFile(p.filePath, []byte(output), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// injectComment injects a comment before the first rule of the specified process.
func (p *FileRulePersister) injectComment(content, processName, comment string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inProcess := false
	inRules := false
	ruleCommentAdded := false

	for _, line := range lines {
		// Detect process name
		if strings.Contains(line, "name:") && strings.Contains(line, processName) {
			inProcess = true
		}

		// Detect rules section
		if inProcess && strings.TrimSpace(line) == "rules:" {
			inRules = true
		}

		// Add comment before first rule entry
		if inProcess && inRules && !ruleCommentAdded && strings.HasPrefix(strings.TrimSpace(line), "- ") {
			indent := strings.Repeat(" ", len(line)-len(strings.TrimLeft(line, " ")))
			result = append(result, indent+"# "+comment)
			ruleCommentAdded = true
		}

		// Reset when we exit the process
		if inProcess && len(line) > 0 && line[0] != ' ' && !strings.HasPrefix(line, "  ") {
			if strings.HasPrefix(line, "-") && !strings.HasPrefix(strings.TrimSpace(line), "- target:") {
				inProcess = false
				inRules = false
			}
		}

		result = append(result, line)
	}

	return strings.Join(result, "\n")
}

// RemoveRule removes a rule from the configuration file.
func (p *FileRulePersister) RemoveRule(processName string, target NetworkTarget) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	config, err := p.loadOrCreateConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Find process config
	for i := range config.Processes {
		if config.Processes[i].Name != processName {
			continue
		}

		// Filter out the matching rule
		var newRules []NetworkTarget
		for _, r := range config.Processes[i].Rules {
			if !(r.Host == target.Host &&
				r.IP == target.IP &&
				r.CIDR == target.CIDR &&
				r.Port == target.Port &&
				r.Protocol == target.Protocol &&
				r.Decision == target.Decision) {
				newRules = append(newRules, r)
			}
		}
		config.Processes[i].Rules = newRules
		break
	}

	return p.writeConfigWithComment(config, "", "")
}

// GetRules returns all rules for a process.
func (p *FileRulePersister) GetRules(processName string) ([]NetworkTarget, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	config, err := p.loadOrCreateConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	for _, pc := range config.Processes {
		if pc.Name == processName {
			return pc.Rules, nil
		}
	}

	return nil, nil
}

// InMemoryRulePersister is an in-memory rule persister for testing.
type InMemoryRulePersister struct {
	mu    sync.Mutex
	rules map[string][]NetworkTarget // processName -> rules
}

// NewInMemoryRulePersister creates a new in-memory rule persister.
func NewInMemoryRulePersister() *InMemoryRulePersister {
	return &InMemoryRulePersister{
		rules: make(map[string][]NetworkTarget),
	}
}

// AddRule adds a rule to the in-memory store.
func (p *InMemoryRulePersister) AddRule(processName string, target NetworkTarget, comment string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if rule already exists
	for _, r := range p.rules[processName] {
		if r.Host == target.Host &&
			r.IP == target.IP &&
			r.CIDR == target.CIDR &&
			r.Port == target.Port &&
			r.Protocol == target.Protocol &&
			r.Decision == target.Decision {
			return nil
		}
	}

	// Add rule at beginning
	p.rules[processName] = append([]NetworkTarget{target}, p.rules[processName]...)
	return nil
}

// GetRules returns all rules for a process.
func (p *InMemoryRulePersister) GetRules(processName string) []NetworkTarget {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rules[processName]
}

// Clear clears all rules.
func (p *InMemoryRulePersister) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = make(map[string][]NetworkTarget)
}
