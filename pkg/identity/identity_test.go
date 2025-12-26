package identity

import (
	"testing"
	"time"
)

func TestAuthMethod_IsValid(t *testing.T) {
	tests := []struct {
		method AuthMethod
		valid  bool
	}{
		{AuthAPIKey, true},
		{AuthJWT, true},
		{AuthMTLS, true},
		{AuthOIDC, true},
		{AuthMethod("unknown"), false},
		{AuthMethod(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			if got := tt.method.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestTrustLevel_IsValid(t *testing.T) {
	tests := []struct {
		level TrustLevel
		valid bool
	}{
		{TrustUntrusted, true},
		{TrustLimited, true},
		{TrustTrusted, true},
		{TrustInternal, true},
		{TrustLevel("unknown"), false},
		{TrustLevel(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			if got := tt.level.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestTrustLevel_PolicyStrictness(t *testing.T) {
	tests := []struct {
		level      TrustLevel
		strictness int
	}{
		{TrustInternal, 0},
		{TrustTrusted, 1},
		{TrustLimited, 2},
		{TrustUntrusted, 3},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			if got := tt.level.PolicyStrictness(); got != tt.strictness {
				t.Errorf("PolicyStrictness() = %v, want %v", got, tt.strictness)
			}
		})
	}

	// Verify ordering
	if TrustUntrusted.PolicyStrictness() <= TrustLimited.PolicyStrictness() {
		t.Error("TrustUntrusted should be stricter than TrustLimited")
	}
	if TrustLimited.PolicyStrictness() <= TrustTrusted.PolicyStrictness() {
		t.Error("TrustLimited should be stricter than TrustTrusted")
	}
}

func TestNewAgentIdentity(t *testing.T) {
	agent, err := NewAgentIdentity("agent1", "Test Agent", "tenant1")
	if err != nil {
		t.Fatalf("NewAgentIdentity: %v", err)
	}

	if agent.AgentID != "agent1" {
		t.Errorf("AgentID = %s, want agent1", agent.AgentID)
	}
	if agent.Name != "Test Agent" {
		t.Errorf("Name = %s, want Test Agent", agent.Name)
	}
	if agent.TenantID != "tenant1" {
		t.Errorf("TenantID = %s, want tenant1", agent.TenantID)
	}
	if agent.AuthMethod != AuthAPIKey {
		t.Errorf("AuthMethod = %s, want api_key", agent.AuthMethod)
	}
	if agent.TrustLevel != TrustLimited {
		t.Errorf("TrustLevel = %s, want limited", agent.TrustLevel)
	}
	if !agent.Enabled {
		t.Error("expected Enabled = true")
	}
}

func TestNewAgentIdentity_InvalidID(t *testing.T) {
	tests := []struct {
		agentID  string
		tenantID string
		wantErr  error
	}{
		{"", "tenant1", ErrInvalidAgentID},
		{"123agent", "tenant1", ErrInvalidAgentID}, // Must start with letter
		{"agent with spaces", "tenant1", ErrInvalidAgentID},
		{"agent1", "", ErrInvalidTenantID},
		{"agent1", "123tenant", ErrInvalidTenantID},
	}

	for _, tt := range tests {
		t.Run(tt.agentID+"/"+tt.tenantID, func(t *testing.T) {
			_, err := NewAgentIdentity(tt.agentID, "Test", tt.tenantID)
			if err != tt.wantErr {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgentIdentity_Roles(t *testing.T) {
	agent, _ := NewAgentIdentity("agent1", "Test", "tenant1")

	// Initially no roles
	if agent.HasRole("admin") {
		t.Error("should not have admin role initially")
	}

	// Add role
	agent.AddRole("admin")
	if !agent.HasRole("admin") {
		t.Error("should have admin role after adding")
	}

	// Add duplicate (should be no-op)
	agent.AddRole("admin")
	if len(agent.Roles) != 1 {
		t.Errorf("len(Roles) = %d, want 1", len(agent.Roles))
	}

	// Add another role
	agent.AddRole("user")
	if len(agent.Roles) != 2 {
		t.Errorf("len(Roles) = %d, want 2", len(agent.Roles))
	}

	// Remove role
	agent.RemoveRole("admin")
	if agent.HasRole("admin") {
		t.Error("should not have admin role after removing")
	}
	if !agent.HasRole("user") {
		t.Error("should still have user role")
	}
}

func TestAgentIdentity_GenerateAPIKey(t *testing.T) {
	agent, _ := NewAgentIdentity("agent1", "Test", "tenant1")

	key, err := agent.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	// Check format
	if !IsAPIKeyFormat(key) {
		t.Errorf("key %s does not match expected format", key)
	}

	// Validate key
	if !agent.ValidateAPIKey(key) {
		t.Error("ValidateAPIKey should return true for generated key")
	}

	// Wrong key should fail
	if agent.ValidateAPIKey("wrong") {
		t.Error("ValidateAPIKey should return false for wrong key")
	}
}

func TestAgentIdentity_Touch(t *testing.T) {
	agent, _ := NewAgentIdentity("agent1", "Test", "tenant1")

	if agent.LastSeenAt != nil {
		t.Error("LastSeenAt should be nil initially")
	}

	agent.Touch()

	if agent.LastSeenAt == nil {
		t.Error("LastSeenAt should be set after Touch")
	}

	now := time.Now().UTC()
	if agent.LastSeenAt.After(now) {
		t.Error("LastSeenAt should not be in the future")
	}
}

func TestAgentIdentity_String(t *testing.T) {
	agent, _ := NewAgentIdentity("agent1", "Test", "tenant1")

	if got := agent.String(); got != "agent1@tenant1" {
		t.Errorf("String() = %s, want agent1@tenant1", got)
	}
}

func TestIsAPIKeyFormat(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"agsh_" + "a" + string(make([]byte, 64)), false}, // Wrong content
		{"agsh_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{"wrong_prefix", false},
		{"agsh_short", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key[:min(20, len(tt.key))], func(t *testing.T) {
			if got := IsAPIKeyFormat(tt.key); got != tt.valid {
				t.Errorf("IsAPIKeyFormat() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestInMemoryStore_CRUD(t *testing.T) {
	store := NewInMemoryStore()

	agent, _ := NewAgentIdentity("agent1", "Test", "tenant1")
	agent.GenerateAPIKey()

	// Save
	if err := store.Save(agent); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Get
	got, err := store.Get("agent1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AgentID != agent.AgentID {
		t.Errorf("AgentID = %s, want %s", got.AgentID, agent.AgentID)
	}

	// List
	list, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("len(List) = %d, want 1", len(list))
	}

	// GetByTenant
	byTenant, err := store.GetByTenant("tenant1")
	if err != nil {
		t.Fatalf("GetByTenant: %v", err)
	}
	if len(byTenant) != 1 {
		t.Errorf("len(GetByTenant) = %d, want 1", len(byTenant))
	}

	// Delete
	if err := store.Delete("agent1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Get after delete should fail
	_, err = store.Get("agent1")
	if err != ErrAgentNotFound {
		t.Errorf("Get after Delete: err = %v, want ErrAgentNotFound", err)
	}
}

func TestInMemoryStore_ValidateCredentials(t *testing.T) {
	store := NewInMemoryStore()

	agent, _ := NewAgentIdentity("agent1", "Test", "tenant1")
	key, _ := agent.GenerateAPIKey()
	store.Save(agent)

	// Valid key
	got, err := store.ValidateCredentials(key)
	if err != nil {
		t.Fatalf("ValidateCredentials: %v", err)
	}
	if got.AgentID != agent.AgentID {
		t.Errorf("AgentID = %s, want %s", got.AgentID, agent.AgentID)
	}

	// Invalid key
	_, err = store.ValidateCredentials("wrong")
	if err != ErrInvalidAPIKey {
		t.Errorf("ValidateCredentials(wrong): err = %v, want ErrInvalidAPIKey", err)
	}

	// Disabled agent
	agent.Enabled = false
	store.Save(agent)
	_, err = store.ValidateCredentials(key)
	if err != ErrAgentDisabled {
		t.Errorf("ValidateCredentials(disabled): err = %v, want ErrAgentDisabled", err)
	}
}

func TestRegistry_Register(t *testing.T) {
	store := NewInMemoryStore()
	registry := NewRegistry(store)

	var registered *AgentIdentity
	registry.OnRegister(func(a *AgentIdentity) {
		registered = a
	})

	agent, key, err := registry.Register("agent1", "Test Agent", "tenant1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if agent.AgentID != "agent1" {
		t.Errorf("AgentID = %s, want agent1", agent.AgentID)
	}
	if !IsAPIKeyFormat(key) {
		t.Error("expected valid API key format")
	}
	if registered == nil || registered.AgentID != "agent1" {
		t.Error("OnRegister callback not called correctly")
	}
}

func TestRegistry_Authenticate(t *testing.T) {
	store := NewInMemoryStore()
	registry := NewRegistry(store)

	agent, key, _ := registry.Register("agent1", "Test", "tenant1")

	// Authenticate
	got, err := registry.Authenticate(key)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.AgentID != agent.AgentID {
		t.Errorf("AgentID = %s, want %s", got.AgentID, agent.AgentID)
	}
	if got.LastSeenAt == nil {
		t.Error("LastSeenAt should be set after Authenticate")
	}
}

func TestRegistry_ActiveAgents(t *testing.T) {
	store := NewInMemoryStore()
	registry := NewRegistry(store)

	// Create agents
	agent1, key1, _ := registry.Register("agent1", "Test1", "tenant1")
	registry.Register("agent2", "Test2", "tenant1")

	// Only authenticate agent1
	registry.Authenticate(key1)

	// Check active agents
	active, err := registry.ActiveAgents(time.Hour)
	if err != nil {
		t.Fatalf("ActiveAgents: %v", err)
	}
	if len(active) != 1 {
		t.Errorf("len(ActiveAgents) = %d, want 1", len(active))
	}
	if active[0].AgentID != agent1.AgentID {
		t.Errorf("active agent = %s, want %s", active[0].AgentID, agent1.AgentID)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
