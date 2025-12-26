package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// PolicyInfo represents a named policy configuration.
type PolicyInfo struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Type        string         `json:"type"` // "file", "network", "command", "env"
	Rules       []PolicyRule   `json:"rules"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// PolicyRule represents a single policy rule.
type PolicyRule struct {
	Name           string   `json:"name"`
	Patterns       []string `json:"patterns,omitempty"`
	Paths          []string `json:"paths,omitempty"`
	Operations     []string `json:"operations,omitempty"`
	Commands       []string `json:"commands,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	CIDRs          []string `json:"cidrs,omitempty"`
	Ports          []int    `json:"ports,omitempty"`
	Action         string   `json:"action"` // "allow", "deny", "approve", "redirect"
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// PolicyValidationResult represents the result of policy validation.
type PolicyValidationResult struct {
	Valid   bool              `json:"valid"`
	Errors  []ValidationError `json:"errors,omitempty"`
	Warning []string          `json:"warnings,omitempty"`
}

// ValidationError represents a single validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Rule    string `json:"rule,omitempty"`
}

// CreatePolicyRequest represents a request to create a policy.
type CreatePolicyRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Type        string         `json:"type"`
	Rules       []PolicyRule   `json:"rules"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// UpdatePolicyRequest represents a request to update a policy.
type UpdatePolicyRequest struct {
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Rules       []PolicyRule   `json:"rules,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// listPolicies returns all configured policies.
func (a *App) listPolicies(w http.ResponseWriter, r *http.Request) {
	// Get policies from the policy engine
	// For now, return the current policy configuration
	policies := a.getPoliciesFromEngine()
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies,
		"count":    len(policies),
	})
}

// getPolicy returns a specific policy by ID.
func (a *App) getPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "policyId")
	if policyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy ID required"})
		return
	}

	policy := a.findPolicyByID(policyID)
	if policy == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy not found"})
		return
	}

	writeJSON(w, http.StatusOK, policy)
}

// createPolicy creates a new policy.
func (a *App) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	// Validate request
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}
	if req.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "type is required"})
		return
	}

	// Validate the policy rules
	result := validatePolicyRules(req.Type, req.Rules)
	if !result.Valid {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":      "invalid policy rules",
			"validation": result,
		})
		return
	}

	now := time.Now().UTC()
	policy := PolicyInfo{
		ID:          "policy-" + uuid.NewString()[:8],
		Name:        req.Name,
		Description: req.Description,
		Type:        req.Type,
		Rules:       req.Rules,
		CreatedAt:   now,
		UpdatedAt:   now,
		Metadata:    req.Metadata,
	}

	// Store the policy (in-memory for now, would be persisted in production)
	a.storePolicyInfo(policy)

	// Emit event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: now,
		Type:      "policy_created",
		Fields: map[string]any{
			"policy_id":   policy.ID,
			"policy_name": policy.Name,
			"policy_type": policy.Type,
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

	writeJSON(w, http.StatusCreated, policy)
}

// updatePolicy updates an existing policy.
func (a *App) updatePolicy(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "policyId")
	if policyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy ID required"})
		return
	}

	existing := a.findPolicyByID(policyID)
	if existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy not found"})
		return
	}

	var req UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	// Update fields if provided
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if len(req.Rules) > 0 {
		// Validate new rules
		result := validatePolicyRules(existing.Type, req.Rules)
		if !result.Valid {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":      "invalid policy rules",
				"validation": result,
			})
			return
		}
		existing.Rules = req.Rules
	}
	if req.Metadata != nil {
		existing.Metadata = req.Metadata
	}
	existing.UpdatedAt = time.Now().UTC()

	// Store updated policy
	a.storePolicyInfo(*existing)

	// Emit event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: existing.UpdatedAt,
		Type:      "policy_updated",
		Fields: map[string]any{
			"policy_id":   existing.ID,
			"policy_name": existing.Name,
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

	writeJSON(w, http.StatusOK, existing)
}

// deletePolicy removes a policy.
func (a *App) deletePolicy(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "policyId")
	if policyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy ID required"})
		return
	}

	if !a.removePolicyByID(policyID) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "policy not found"})
		return
	}

	// Emit event
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "policy_deleted",
		Fields: map[string]any{
			"policy_id": policyID,
		},
	}
	_ = a.store.AppendEvent(r.Context(), ev)
	a.broker.Publish(ev)

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// validatePolicy validates a policy without applying it.
func (a *App) validatePolicy(w http.ResponseWriter, r *http.Request) {
	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}

	result := validatePolicyRules(req.Type, req.Rules)
	writeJSON(w, http.StatusOK, result)
}

// validatePolicyRules validates policy rules and returns validation result.
func validatePolicyRules(policyType string, rules []PolicyRule) PolicyValidationResult {
	result := PolicyValidationResult{Valid: true}

	validActions := map[string]bool{
		"allow": true, "deny": true, "approve": true, "redirect": true,
	}
	validTypes := map[string]bool{
		"file": true, "network": true, "command": true, "env": true, "dns": true,
	}

	if !validTypes[policyType] {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Field:   "type",
			Message: "invalid policy type, must be one of: file, network, command, env, dns",
		})
	}

	for i, rule := range rules {
		if rule.Name == "" {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   "rules",
				Message: "rule name is required",
				Rule:    "",
			})
		}

		if !validActions[rule.Action] {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   "rules",
				Message: "invalid action, must be one of: allow, deny, approve, redirect",
				Rule:    rule.Name,
			})
		}

		// Type-specific validation
		switch policyType {
		case "file":
			if len(rule.Paths) == 0 && len(rule.Patterns) == 0 {
				result.Warning = append(result.Warning,
					"rule "+rule.Name+" has no paths or patterns, will match nothing")
			}
		case "network":
			if len(rule.Domains) == 0 && len(rule.CIDRs) == 0 && len(rule.Ports) == 0 {
				result.Warning = append(result.Warning,
					"rule "+rule.Name+" has no domains, CIDRs, or ports, will match nothing")
			}
		case "command":
			if len(rule.Commands) == 0 && len(rule.Patterns) == 0 {
				result.Warning = append(result.Warning,
					"rule "+rule.Name+" has no commands or patterns, will match nothing")
			}
		}

		// Timeout validation for approve action
		if rule.Action == "approve" && rule.TimeoutSeconds <= 0 {
			result.Warning = append(result.Warning,
				"rule "+rule.Name+" with approve action has no timeout, will use default")
		}

		_ = i // silence unused variable warning
	}

	return result
}

// In-memory policy storage (would be replaced with persistent storage)
var (
	policyStore   = make(map[string]PolicyInfo)
	policyStoreMu = make(chan struct{}, 1)
)

func init() {
	policyStoreMu <- struct{}{}
}

func (a *App) getPoliciesFromEngine() []PolicyInfo {
	<-policyStoreMu
	defer func() { policyStoreMu <- struct{}{} }()

	policies := make([]PolicyInfo, 0, len(policyStore))
	for _, p := range policyStore {
		policies = append(policies, p)
	}
	return policies
}

func (a *App) findPolicyByID(id string) *PolicyInfo {
	<-policyStoreMu
	defer func() { policyStoreMu <- struct{}{} }()

	if p, ok := policyStore[id]; ok {
		return &p
	}
	return nil
}

func (a *App) storePolicyInfo(p PolicyInfo) {
	<-policyStoreMu
	defer func() { policyStoreMu <- struct{}{} }()
	policyStore[p.ID] = p
}

func (a *App) removePolicyByID(id string) bool {
	<-policyStoreMu
	defer func() { policyStoreMu <- struct{}{} }()

	if _, ok := policyStore[id]; ok {
		delete(policyStore, id)
		return true
	}
	return false
}
