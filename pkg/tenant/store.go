package tenant

import (
	"sync"
)

// Store provides storage and retrieval of tenant configurations.
type Store interface {
	// Get retrieves a tenant configuration by ID.
	Get(tenantID string) (*TenantConfig, error)

	// Save persists a tenant configuration.
	Save(tenant *TenantConfig) error

	// Delete removes a tenant configuration.
	Delete(tenantID string) error

	// List returns all tenant configurations.
	List() ([]*TenantConfig, error)

	// GetUsage retrieves tenant usage statistics.
	GetUsage(tenantID string) (*TenantUsage, error)

	// SaveUsage persists tenant usage statistics.
	SaveUsage(usage *TenantUsage) error
}

// InMemoryStore provides an in-memory implementation of Store.
type InMemoryStore struct {
	mu      sync.RWMutex
	tenants map[string]*TenantConfig
	usage   map[string]*TenantUsage
}

// NewInMemoryStore creates a new in-memory tenant store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		tenants: make(map[string]*TenantConfig),
		usage:   make(map[string]*TenantUsage),
	}
}

// Get retrieves a tenant configuration by ID.
func (s *InMemoryStore) Get(tenantID string) (*TenantConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenant, ok := s.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// Save persists a tenant configuration.
func (s *InMemoryStore) Save(tenant *TenantConfig) error {
	if err := tenant.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tenants[tenant.TenantID] = tenant

	// Initialize usage if not exists
	if _, ok := s.usage[tenant.TenantID]; !ok {
		s.usage[tenant.TenantID] = NewTenantUsage(tenant.TenantID)
	}

	return nil
}

// Delete removes a tenant configuration.
func (s *InMemoryStore) Delete(tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.tenants[tenantID]; !ok {
		return ErrTenantNotFound
	}

	delete(s.tenants, tenantID)
	delete(s.usage, tenantID)

	return nil
}

// List returns all tenant configurations.
func (s *InMemoryStore) List() ([]*TenantConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tenants := make([]*TenantConfig, 0, len(s.tenants))
	for _, tenant := range s.tenants {
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}

// GetUsage retrieves tenant usage statistics.
func (s *InMemoryStore) GetUsage(tenantID string) (*TenantUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	usage, ok := s.usage[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	return usage, nil
}

// SaveUsage persists tenant usage statistics.
func (s *InMemoryStore) SaveUsage(usage *TenantUsage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.usage[usage.TenantID] = usage
	return nil
}

// Count returns the total number of tenants.
func (s *InMemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tenants)
}

// Manager provides high-level tenant management operations.
type Manager struct {
	store Store
	mu    sync.RWMutex

	// Callbacks for tenant lifecycle events
	onCreate func(*TenantConfig)
	onDelete func(*TenantConfig)
}

// NewManager creates a new tenant manager.
func NewManager(store Store) *Manager {
	return &Manager{
		store: store,
	}
}

// OnCreate sets a callback for when tenants are created.
func (m *Manager) OnCreate(fn func(*TenantConfig)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onCreate = fn
}

// OnDelete sets a callback for when tenants are deleted.
func (m *Manager) OnDelete(fn func(*TenantConfig)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onDelete = fn
}

// Create creates a new tenant with default settings.
func (m *Manager) Create(tenantID, name string) (*TenantConfig, error) {
	tenant, err := NewTenantConfig(tenantID, name)
	if err != nil {
		return nil, err
	}

	// Check if already exists
	if existing, _ := m.store.Get(tenantID); existing != nil {
		return nil, ErrTenantExists
	}

	if err := m.store.Save(tenant); err != nil {
		return nil, err
	}

	// Call callback
	m.mu.RLock()
	callback := m.onCreate
	m.mu.RUnlock()

	if callback != nil {
		callback(tenant)
	}

	return tenant, nil
}

// Get retrieves a tenant by ID.
func (m *Manager) Get(tenantID string) (*TenantConfig, error) {
	return m.store.Get(tenantID)
}

// Update updates a tenant configuration.
func (m *Manager) Update(tenant *TenantConfig) error {
	return m.store.Save(tenant)
}

// Delete removes a tenant.
func (m *Manager) Delete(tenantID string) error {
	// Get tenant first for callback
	tenant, err := m.store.Get(tenantID)
	if err != nil {
		return err
	}

	if err := m.store.Delete(tenantID); err != nil {
		return err
	}

	// Call callback
	m.mu.RLock()
	callback := m.onDelete
	m.mu.RUnlock()

	if callback != nil {
		callback(tenant)
	}

	return nil
}

// List returns all tenants.
func (m *Manager) List() ([]*TenantConfig, error) {
	return m.store.List()
}

// GetUsage retrieves usage statistics for a tenant.
func (m *Manager) GetUsage(tenantID string) (*TenantUsage, error) {
	return m.store.GetUsage(tenantID)
}

// CheckQuota checks if an action is allowed within tenant quotas.
func (m *Manager) CheckQuota(tenantID string, action QuotaAction) error {
	tenant, err := m.store.Get(tenantID)
	if err != nil {
		return err
	}

	if !tenant.Enabled {
		return ErrTenantDisabled
	}

	usage, err := m.store.GetUsage(tenantID)
	if err != nil {
		return err
	}

	switch action {
	case QuotaActionStartSession:
		return usage.CanStartSession(tenant.Quotas)
	case QuotaActionRegisterAgent:
		return usage.CanRegisterAgent(tenant.Quotas)
	case QuotaActionAPICall:
		return usage.CanMakeAPICall(tenant.Quotas)
	default:
		return nil
	}
}

// RecordUsage records resource usage for a tenant.
func (m *Manager) RecordUsage(tenantID string, action QuotaAction, amount int64) error {
	usage, err := m.store.GetUsage(tenantID)
	if err != nil {
		return err
	}

	switch action {
	case QuotaActionAPICall:
		usage.RecordAPICall()
	case QuotaActionNetworkBytes:
		usage.RecordNetworkBytes(amount)
	case QuotaActionStartSession:
		usage.ActiveSessions++
	case QuotaActionEndSession:
		if usage.ActiveSessions > 0 {
			usage.ActiveSessions--
		}
	case QuotaActionRegisterAgent:
		usage.ActiveAgents++
	case QuotaActionUnregisterAgent:
		if usage.ActiveAgents > 0 {
			usage.ActiveAgents--
		}
	}

	return m.store.SaveUsage(usage)
}

// QuotaAction represents an action that consumes quota.
type QuotaAction int

const (
	QuotaActionStartSession QuotaAction = iota
	QuotaActionEndSession
	QuotaActionRegisterAgent
	QuotaActionUnregisterAgent
	QuotaActionAPICall
	QuotaActionNetworkBytes
)
