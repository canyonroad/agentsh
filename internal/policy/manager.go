package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"gopkg.in/yaml.v3"
)

// Manager selects and loads a policy once, based on config and env.
type Manager struct {
	selectedName string
	dir          string
	manifestPath string
	once         sync.Once
	policy       *Policy
	err          error
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// NewManager binds the policy name but defers file I/O until first Get().
// envName is the value of AGENTSH_POLICY_NAME (already read from environment).
func NewManager(dir, defaultName string, allowed []string, manifestPath, envName string) *Manager {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, n := range allowed {
		allowedSet[n] = struct{}{}
	}

	selected := defaultName
	if envName != "" && nameRe.MatchString(envName) {
		if _, ok := allowedSet[envName]; ok || len(allowedSet) == 0 && envName == defaultName {
			selected = envName
		}
	}

	return &Manager{
		selectedName: selected,
		dir:          dir,
		manifestPath: manifestPath,
	}
}

// SelectedName returns the bound policy name (without suffix).
func (m *Manager) SelectedName() string {
	if m == nil {
		return ""
	}
	return m.selectedName
}

// Get loads and returns the active policy, caching the result.
func (m *Manager) Get() (*Policy, error) {
	m.once.Do(func() {
		path, err := ResolvePolicyPath(m.dir, m.selectedName)
		if err != nil {
			m.err = err
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			m.err = fmt.Errorf("read policy: %w", err)
			return
		}
		if m.manifestPath != "" {
			if err := verifyHash(path, data, m.manifestPath); err != nil {
				m.err = err
				return
			}
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var p Policy
		if err := dec.Decode(&p); err != nil {
			m.err = fmt.Errorf("parse policy: %w", err)
			return
		}
		if err := p.Validate(); err != nil {
			m.err = fmt.Errorf("validate policy: %w", err)
			return
		}
		m.policy = &p
	})
	return m.policy, m.err
}

func verifyHash(path string, data []byte, manifestPath string) error {
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	lines := bytes.Split(bytes.TrimSpace(manifest), []byte{'\n'})
	base := filepath.Base(path)
	expected := ""
	for _, ln := range lines {
		fields := bytes.Fields(ln)
		if len(fields) >= 2 && string(fields[1]) == base {
			expected = string(fields[0])
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("policy not listed in manifest: %s", base)
	}
	actual := sha256.Sum256(data)
	if expected != hex.EncodeToString(actual[:]) {
		return fmt.Errorf("policy hash mismatch: %s", base)
	}
	return nil
}
