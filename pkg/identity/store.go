package identity

import (
	"sync"
	"time"
)

// Store provides storage and retrieval of agent identities.
type Store interface {
	// Get retrieves an agent identity by ID.
	Get(agentID string) (*AgentIdentity, error)

	// GetByTenant retrieves all agents for a tenant.
	GetByTenant(tenantID string) ([]*AgentIdentity, error)

	// Save persists an agent identity.
	Save(agent *AgentIdentity) error

	// Delete removes an agent identity.
	Delete(agentID string) error

	// List returns all agent identities.
	List() ([]*AgentIdentity, error)

	// ValidateCredentials validates agent credentials and returns the identity.
	ValidateCredentials(apiKey string) (*AgentIdentity, error)
}

// InMemoryStore provides an in-memory implementation of Store.
type InMemoryStore struct {
	mu       sync.RWMutex
	agents   map[string]*AgentIdentity
	byTenant map[string][]string // tenantID -> []agentID
	byAPIKey map[string]string   // apiKey -> agentID
}

// NewInMemoryStore creates a new in-memory identity store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		agents:   make(map[string]*AgentIdentity),
		byTenant: make(map[string][]string),
		byAPIKey: make(map[string]string),
	}
}

// Get retrieves an agent identity by ID.
func (s *InMemoryStore) Get(agentID string) (*AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, ok := s.agents[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return agent, nil
}

// GetByTenant retrieves all agents for a tenant.
func (s *InMemoryStore) GetByTenant(tenantID string) ([]*AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agentIDs, ok := s.byTenant[tenantID]
	if !ok {
		return nil, nil
	}

	agents := make([]*AgentIdentity, 0, len(agentIDs))
	for _, id := range agentIDs {
		if agent, ok := s.agents[id]; ok {
			agents = append(agents, agent)
		}
	}
	return agents, nil
}

// Save persists an agent identity.
func (s *InMemoryStore) Save(agent *AgentIdentity) error {
	if err := agent.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if this is a new agent or update
	existing, exists := s.agents[agent.AgentID]

	// If updating, remove old API key mapping
	if exists && existing.APIKey != "" && existing.APIKey != agent.APIKey {
		delete(s.byAPIKey, existing.APIKey)
	}

	// If updating and tenant changed, update tenant mapping
	if exists && existing.TenantID != agent.TenantID {
		s.removeTenantMapping(existing.TenantID, agent.AgentID)
	}

	// Store the agent
	s.agents[agent.AgentID] = agent

	// Update tenant mapping if new or tenant changed
	if !exists || existing.TenantID != agent.TenantID {
		s.addTenantMapping(agent.TenantID, agent.AgentID)
	}

	// Update API key mapping
	if agent.APIKey != "" {
		s.byAPIKey[agent.APIKey] = agent.AgentID
	}

	return nil
}

// Delete removes an agent identity.
func (s *InMemoryStore) Delete(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}

	// Remove from tenant mapping
	s.removeTenantMapping(agent.TenantID, agentID)

	// Remove API key mapping
	if agent.APIKey != "" {
		delete(s.byAPIKey, agent.APIKey)
	}

	// Remove agent
	delete(s.agents, agentID)

	return nil
}

// List returns all agent identities.
func (s *InMemoryStore) List() ([]*AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agents := make([]*AgentIdentity, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, agent)
	}
	return agents, nil
}

// ValidateCredentials validates agent credentials and returns the identity.
func (s *InMemoryStore) ValidateCredentials(apiKey string) (*AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agentID, ok := s.byAPIKey[apiKey]
	if !ok {
		return nil, ErrInvalidAPIKey
	}

	agent, ok := s.agents[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}

	if !agent.Enabled {
		return nil, ErrAgentDisabled
	}

	return agent, nil
}

// addTenantMapping adds an agent to the tenant index (must hold lock).
func (s *InMemoryStore) addTenantMapping(tenantID, agentID string) {
	s.byTenant[tenantID] = append(s.byTenant[tenantID], agentID)
}

// removeTenantMapping removes an agent from the tenant index (must hold lock).
func (s *InMemoryStore) removeTenantMapping(tenantID, agentID string) {
	agents := s.byTenant[tenantID]
	for i, id := range agents {
		if id == agentID {
			s.byTenant[tenantID] = append(agents[:i], agents[i+1:]...)
			break
		}
	}
}

// Count returns the total number of agents.
func (s *InMemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.agents)
}

// CountByTenant returns the number of agents for a tenant.
func (s *InMemoryStore) CountByTenant(tenantID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byTenant[tenantID])
}

// Additional errors
var (
	ErrAgentNotFound = NewError("agent not found")
	ErrAgentDisabled = NewError("agent is disabled")
	ErrAgentExists   = NewError("agent already exists")
)

// Error is a custom error type for the identity package.
type Error struct {
	message string
}

// NewError creates a new identity error.
func NewError(msg string) *Error {
	return &Error{message: msg}
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.message
}

// Registry manages agent registration and lookup.
type Registry struct {
	store Store
	mu    sync.RWMutex

	// Callbacks for agent lifecycle events
	onRegister   func(*AgentIdentity)
	onUnregister func(*AgentIdentity)
}

// NewRegistry creates a new agent registry.
func NewRegistry(store Store) *Registry {
	return &Registry{
		store: store,
	}
}

// OnRegister sets a callback for when agents are registered.
func (r *Registry) OnRegister(fn func(*AgentIdentity)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRegister = fn
}

// OnUnregister sets a callback for when agents are unregistered.
func (r *Registry) OnUnregister(fn func(*AgentIdentity)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onUnregister = fn
}

// Register creates and registers a new agent.
func (r *Registry) Register(agentID, name, tenantID string) (*AgentIdentity, string, error) {
	agent, err := NewAgentIdentity(agentID, name, tenantID)
	if err != nil {
		return nil, "", err
	}

	// Generate API key
	apiKey, err := agent.GenerateAPIKey()
	if err != nil {
		return nil, "", err
	}

	// Save to store
	if err := r.store.Save(agent); err != nil {
		return nil, "", err
	}

	// Call callback
	r.mu.RLock()
	callback := r.onRegister
	r.mu.RUnlock()

	if callback != nil {
		callback(agent)
	}

	return agent, apiKey, nil
}

// Unregister removes an agent from the registry.
func (r *Registry) Unregister(agentID string) error {
	// Get agent first for callback
	agent, err := r.store.Get(agentID)
	if err != nil {
		return err
	}

	// Delete from store
	if err := r.store.Delete(agentID); err != nil {
		return err
	}

	// Call callback
	r.mu.RLock()
	callback := r.onUnregister
	r.mu.RUnlock()

	if callback != nil {
		callback(agent)
	}

	return nil
}

// Authenticate validates credentials and returns the agent identity.
func (r *Registry) Authenticate(apiKey string) (*AgentIdentity, error) {
	agent, err := r.store.ValidateCredentials(apiKey)
	if err != nil {
		return nil, err
	}

	// Update last seen
	agent.Touch()

	return agent, nil
}

// Get retrieves an agent by ID.
func (r *Registry) Get(agentID string) (*AgentIdentity, error) {
	return r.store.Get(agentID)
}

// ListByTenant returns all agents for a tenant.
func (r *Registry) ListByTenant(tenantID string) ([]*AgentIdentity, error) {
	return r.store.GetByTenant(tenantID)
}

// ActiveAgents returns agents that have been active within the given duration.
func (r *Registry) ActiveAgents(within time.Duration) ([]*AgentIdentity, error) {
	all, err := r.store.List()
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-within)
	active := make([]*AgentIdentity, 0)

	for _, agent := range all {
		if agent.LastSeenAt != nil && agent.LastSeenAt.After(cutoff) {
			active = append(active, agent)
		}
	}

	return active, nil
}
