package tenant

import (
	"testing"
	"time"
)

func TestNewTenantConfig(t *testing.T) {
	tenant, err := NewTenantConfig("tenant1", "Test Tenant")
	if err != nil {
		t.Fatalf("NewTenantConfig: %v", err)
	}

	if tenant.TenantID != "tenant1" {
		t.Errorf("TenantID = %s, want tenant1", tenant.TenantID)
	}
	if tenant.Name != "Test Tenant" {
		t.Errorf("Name = %s, want Test Tenant", tenant.Name)
	}
	if !tenant.Enabled {
		t.Error("expected Enabled = true")
	}
	if tenant.Isolation.WorkspaceRoot == "" {
		t.Error("WorkspaceRoot should not be empty")
	}
	if tenant.Quotas.MaxConcurrentSessions <= 0 {
		t.Error("MaxConcurrentSessions should be positive")
	}
}

func TestNewTenantConfig_InvalidID(t *testing.T) {
	tests := []struct {
		tenantID string
		wantErr  error
	}{
		{"", ErrInvalidTenantID},
		{"123tenant", ErrInvalidTenantID}, // Must start with letter
		{"tenant with spaces", ErrInvalidTenantID},
		{"tenant@special", ErrInvalidTenantID},
	}

	for _, tt := range tests {
		t.Run(tt.tenantID, func(t *testing.T) {
			_, err := NewTenantConfig(tt.tenantID, "Test")
			if err != tt.wantErr {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestTenantConfig_WorkspacePath(t *testing.T) {
	tenant, _ := NewTenantConfig("tenant1", "Test")
	tenant.Isolation.WorkspaceRoot = "/var/agentsh/tenants/{tenant_id}/agents/{agent_id}/sessions/{session_id}"

	path := tenant.WorkspacePath("agent1", "sess1")
	expected := "/var/agentsh/tenants/tenant1/agents/agent1/sessions/sess1"
	if path != expected {
		t.Errorf("WorkspacePath() = %s, want %s", path, expected)
	}
}

func TestTenantConfig_IsEgressAllowed(t *testing.T) {
	tenant, _ := NewTenantConfig("tenant1", "Test")

	// Empty lists = allow all
	if !tenant.IsEgressAllowed("example.com") {
		t.Error("empty lists should allow all")
	}

	// Add allowed list
	tenant.Isolation.AllowedEgress = []string{"api.example.com", "*.trusted.com"}

	if !tenant.IsEgressAllowed("api.example.com") {
		t.Error("should allow api.example.com")
	}
	if !tenant.IsEgressAllowed("sub.trusted.com") {
		t.Error("should allow sub.trusted.com via wildcard")
	}
	if !tenant.IsEgressAllowed("trusted.com") {
		t.Error("should allow trusted.com via wildcard")
	}
	if tenant.IsEgressAllowed("evil.com") {
		t.Error("should not allow evil.com")
	}

	// Add denied list
	tenant.Isolation.DeniedEgress = []string{"api.example.com"}

	if tenant.IsEgressAllowed("api.example.com") {
		t.Error("should deny api.example.com via denied list")
	}
}

func TestIsolationConfig_Validate(t *testing.T) {
	// Valid config
	iso := DefaultIsolationConfig("tenant1")
	if err := iso.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	// Invalid UID range (too low)
	iso.UIDRange = [2]int{100, 200}
	if err := iso.Validate(); err != ErrInvalidUIDRange {
		t.Errorf("Validate() = %v, want ErrInvalidUIDRange", err)
	}

	// Invalid UID range (end < start)
	iso.UIDRange = [2]int{10000, 9000}
	if err := iso.Validate(); err != ErrInvalidUIDRange {
		t.Errorf("Validate() = %v, want ErrInvalidUIDRange", err)
	}

	// Valid UID range
	iso.UIDRange = [2]int{100000, 100999}
	if err := iso.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestTenantQuotas_Validate(t *testing.T) {
	quotas := DefaultQuotas()
	if err := quotas.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	quotas.MaxStorageBytes = -1
	if err := quotas.Validate(); err != ErrInvalidStorageSize {
		t.Errorf("Validate() = %v, want ErrInvalidStorageSize", err)
	}
}

func TestTenantUsage_Counters(t *testing.T) {
	usage := NewTenantUsage("tenant1")

	// Initial state
	if usage.ActiveSessions != 0 {
		t.Errorf("ActiveSessions = %d, want 0", usage.ActiveSessions)
	}

	// Record API calls
	usage.RecordAPICall()
	usage.RecordAPICall()
	if usage.APICallsThisHour != 2 {
		t.Errorf("APICallsThisHour = %d, want 2", usage.APICallsThisHour)
	}

	// Record network bytes
	usage.RecordNetworkBytes(1000)
	usage.RecordNetworkBytes(500)
	if usage.NetworkBytesToday != 1500 {
		t.Errorf("NetworkBytesToday = %d, want 1500", usage.NetworkBytesToday)
	}
}

func TestTenantUsage_QuotaChecks(t *testing.T) {
	usage := NewTenantUsage("tenant1")
	quotas := TenantQuotas{
		MaxConcurrentSessions: 2,
		MaxConcurrentAgents:   1,
		MaxAPICallsPerHour:    3,
	}

	// Can start sessions
	if err := usage.CanStartSession(quotas); err != nil {
		t.Errorf("CanStartSession: %v", err)
	}

	// Exceed session limit
	usage.ActiveSessions = 2
	if err := usage.CanStartSession(quotas); err != ErrQuotaExceeded {
		t.Errorf("CanStartSession: %v, want ErrQuotaExceeded", err)
	}

	// Exceed agent limit
	usage.ActiveAgents = 1
	if err := usage.CanRegisterAgent(quotas); err != ErrQuotaExceeded {
		t.Errorf("CanRegisterAgent: %v, want ErrQuotaExceeded", err)
	}

	// Exceed API call limit
	usage.APICallsThisHour = 3
	if err := usage.CanMakeAPICall(quotas); err != ErrQuotaExceeded {
		t.Errorf("CanMakeAPICall: %v, want ErrQuotaExceeded", err)
	}
}

func TestInMemoryStore_CRUD(t *testing.T) {
	store := NewInMemoryStore()

	tenant, _ := NewTenantConfig("tenant1", "Test")

	// Save
	if err := store.Save(tenant); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Get
	got, err := store.Get("tenant1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TenantID != tenant.TenantID {
		t.Errorf("TenantID = %s, want %s", got.TenantID, tenant.TenantID)
	}

	// List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("len(List) = %d, want 1", len(list))
	}

	// GetUsage (should be initialized)
	usage, err := store.GetUsage("tenant1")
	if err != nil {
		t.Fatalf("GetUsage: %v", err)
	}
	if usage.TenantID != "tenant1" {
		t.Errorf("usage.TenantID = %s, want tenant1", usage.TenantID)
	}

	// Delete
	if err := store.Delete("tenant1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Get after delete should fail
	_, err = store.Get("tenant1")
	if err != ErrTenantNotFound {
		t.Errorf("Get after Delete: err = %v, want ErrTenantNotFound", err)
	}
}

func TestManager_Create(t *testing.T) {
	store := NewInMemoryStore()
	manager := NewManager(store)

	var created *TenantConfig
	manager.OnCreate(func(tc *TenantConfig) {
		created = tc
	})

	tenant, err := manager.Create("tenant1", "Test Tenant")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if tenant.TenantID != "tenant1" {
		t.Errorf("TenantID = %s, want tenant1", tenant.TenantID)
	}
	if created == nil || created.TenantID != "tenant1" {
		t.Error("OnCreate callback not called correctly")
	}

	// Duplicate should fail
	_, err = manager.Create("tenant1", "Duplicate")
	if err != ErrTenantExists {
		t.Errorf("Create duplicate: err = %v, want ErrTenantExists", err)
	}
}

func TestManager_CheckQuota(t *testing.T) {
	store := NewInMemoryStore()
	manager := NewManager(store)

	tenant, _ := manager.Create("tenant1", "Test")
	tenant.Quotas.MaxConcurrentSessions = 1

	// First session should be allowed
	if err := manager.CheckQuota("tenant1", QuotaActionStartSession); err != nil {
		t.Errorf("CheckQuota: %v", err)
	}

	// Record usage
	manager.RecordUsage("tenant1", QuotaActionStartSession, 0)

	// Second session should be denied
	if err := manager.CheckQuota("tenant1", QuotaActionStartSession); err != ErrQuotaExceeded {
		t.Errorf("CheckQuota: %v, want ErrQuotaExceeded", err)
	}

	// End session
	manager.RecordUsage("tenant1", QuotaActionEndSession, 0)

	// Now should be allowed again
	if err := manager.CheckQuota("tenant1", QuotaActionStartSession); err != nil {
		t.Errorf("CheckQuota after end: %v", err)
	}
}

func TestManager_DisabledTenant(t *testing.T) {
	store := NewInMemoryStore()
	manager := NewManager(store)

	tenant, _ := manager.Create("tenant1", "Test")
	tenant.Enabled = false
	manager.Update(tenant)

	if err := manager.CheckQuota("tenant1", QuotaActionStartSession); err != ErrTenantDisabled {
		t.Errorf("CheckQuota disabled: %v, want ErrTenantDisabled", err)
	}
}

func TestDefaultQuotas(t *testing.T) {
	quotas := DefaultQuotas()

	if quotas.MaxConcurrentSessions <= 0 {
		t.Error("MaxConcurrentSessions should be positive")
	}
	if quotas.MaxSessionDuration <= 0 {
		t.Error("MaxSessionDuration should be positive")
	}
	if quotas.MaxStorageBytes <= 0 {
		t.Error("MaxStorageBytes should be positive")
	}
	if quotas.MaxMemoryBytes <= 0 {
		t.Error("MaxMemoryBytes should be positive")
	}
}

func TestDefaultIsolationConfig(t *testing.T) {
	iso := DefaultIsolationConfig("tenant1")

	if iso.WorkspaceRoot == "" {
		t.Error("WorkspaceRoot should not be empty")
	}
	if !iso.NetworkNamespace {
		t.Error("NetworkNamespace should be true by default")
	}
	if !iso.Seccomp {
		t.Error("Seccomp should be true by default")
	}
	if iso.MaxProcesses <= 0 {
		t.Error("MaxProcesses should be positive")
	}
}

func TestTenantUsage_ResetCounters(t *testing.T) {
	usage := NewTenantUsage("tenant1")
	usage.APICallsThisHour = 100
	usage.NetworkBytesToday = 1000000

	// Set to past hour/day to trigger reset
	usage.LastResetHour = (time.Now().Hour() + 23) % 24 // Previous hour
	usage.LastResetDate = time.Now().Add(-25 * time.Hour).Truncate(24 * time.Hour)

	usage.CheckAndResetCounters()

	if usage.APICallsThisHour != 0 {
		t.Errorf("APICallsThisHour = %d, want 0 after reset", usage.APICallsThisHour)
	}
	if usage.NetworkBytesToday != 0 {
		t.Errorf("NetworkBytesToday = %d, want 0 after reset", usage.NetworkBytesToday)
	}
}
