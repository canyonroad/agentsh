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

	"github.com/agentsh/agentsh/internal/policy/signing"
)

// Manager selects and loads a policy once, based on config and env.
type Manager struct {
	mu             sync.RWMutex
	selectedName   string
	dir            string
	manifestPath   string
	signingMode    string
	trustStorePath string
	policy         *Policy
	err            error
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

// SetSigningConfig configures signature verification for this manager.
// mode is "enforce", "warn", or "off". trustStorePath is a directory of public key JSON files.
func (m *Manager) SetSigningConfig(mode, trustStorePath string) {
	m.signingMode = mode
	m.trustStorePath = trustStorePath
}

// Get loads and returns the active policy, caching the result.
func (m *Manager) Get() (*Policy, error) {
	m.mu.RLock()
	if m.policy != nil || m.err != nil {
		p, e := m.policy, m.err
		m.mu.RUnlock()
		return p, e
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy != nil || m.err != nil {
		return m.policy, m.err
	}
	p, err := m.loadLocked()
	m.policy = p
	m.err = err
	return p, err
}

// Reload forces the next Get() to re-read the policy file from disk.
// Used when the policy has been replaced out-of-band (e.g. a fresh
// snapshot was pushed by the operator via WTP SessionAck). Subsequent
// Get() calls return the new policy; in-flight callers that already
// captured a *Policy are unaffected.
//
// Returns the new policy or the parse/validate error. A Reload error
// also installs itself as the cached err so subsequent Get() calls
// surface the same failure without a re-read.
func (m *Manager) Reload() (*Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.loadLocked()
	m.policy = p
	m.err = err
	return p, err
}

// loadLocked is the actual disk-read + verify + parse. Caller MUST
// hold m.mu in write mode.
func (m *Manager) loadLocked() (*Policy, error) {
	path, err := ResolvePolicyPath(m.dir, m.selectedName)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if m.manifestPath != "" {
		if err := verifyHash(path, data, m.manifestPath); err != nil {
			return nil, err
		}
	}
	if m.signingMode != "" && m.signingMode != "off" {
		if m.trustStorePath == "" {
			if m.signingMode == "enforce" {
				return nil, fmt.Errorf("signing verification: trust_store not configured")
			}
			fmt.Fprintf(os.Stderr, "WARNING: signing mode is %q but trust_store not configured\n", m.signingMode)
		} else if err := m.verifySigning(path, data); err != nil {
			if m.signingMode == "enforce" {
				return nil, fmt.Errorf("signing verification: %w", err)
			}
			fmt.Fprintf(os.Stderr, "WARNING: policy signing verification failed: %v\n", err)
		}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return &p, nil
}

func (m *Manager) verifySigning(path string, data []byte) error {
	ts, err := signing.LoadTrustStore(m.trustStorePath, m.signingMode == "enforce")
	if err != nil {
		return fmt.Errorf("load trust store: %w", err)
	}
	_, err = signing.VerifyPolicyBytes(data, path+".sig", ts)
	return err
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
