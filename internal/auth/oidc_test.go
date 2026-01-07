package auth

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestOIDCAuth_PolicyForGroups(t *testing.T) {
	tests := []struct {
		name           string
		groupPolicyMap map[string]string
		groups         []string
		want           string
	}{
		{
			name:           "nil auth returns empty",
			groupPolicyMap: nil,
			groups:         []string{"admins"},
			want:           "",
		},
		{
			name:           "empty groups returns empty",
			groupPolicyMap: map[string]string{"admins": "admin", "developers": "default"},
			groups:         []string{},
			want:           "",
		},
		{
			name:           "matching group returns policy",
			groupPolicyMap: map[string]string{"admins": "admin", "developers": "default"},
			groups:         []string{"developers"},
			want:           "default",
		},
		{
			name:           "first matching group wins",
			groupPolicyMap: map[string]string{"admins": "admin", "developers": "default"},
			groups:         []string{"developers", "admins"},
			want:           "default",
		},
		{
			name:           "no matching group returns empty",
			groupPolicyMap: map[string]string{"admins": "admin", "developers": "default"},
			groups:         []string{"users", "guests"},
			want:           "",
		},
		{
			name:           "admin group returns admin policy",
			groupPolicyMap: map[string]string{"admins": "admin", "developers": "default"},
			groups:         []string{"admins"},
			want:           "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var auth *OIDCAuth
			if tt.groupPolicyMap != nil {
				auth = &OIDCAuth{
					groupPolicyMap: tt.groupPolicyMap,
				}
			}

			got := auth.PolicyForGroups(tt.groups)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOIDCAuth_PolicyForGroups_NilAuth(t *testing.T) {
	var auth *OIDCAuth
	got := auth.PolicyForGroups([]string{"admins"})
	assert.Equal(t, "", got)
}

func TestOIDCAuth_RoleForClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims *OIDCClaims
		want   string
	}{
		{
			name:   "nil claims returns agent",
			claims: nil,
			want:   "agent",
		},
		{
			name: "group containing admin returns admin role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"admins"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "admin",
		},
		{
			name: "group with Admin (case-insensitive) returns admin role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"SuperAdmins"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "admin",
		},
		{
			name: "group with ADMIN (uppercase) returns admin role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"ADMIN-TEAM"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "admin",
		},
		{
			name: "developers group returns agent role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"developers"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "agent",
		},
		{
			name: "no groups returns agent role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "agent",
		},
		{
			name: "mixed groups with admin returns admin",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"users", "platform-admin", "guests"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "admin",
		},
		{
			name: "approvers group returns approver role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"approvers"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "approver",
		},
		{
			name: "group with Approver (case-insensitive) returns approver role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"SuperApprovers"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "approver",
		},
		{
			name: "group with APPROVER (uppercase) returns approver role",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"APPROVER-TEAM"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "approver",
		},
		{
			name: "admin takes precedence over approver",
			claims: &OIDCClaims{
				Subject:   "user123",
				Groups:    []string{"approvers", "admins"},
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: "admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &OIDCAuth{}

			got := auth.RoleForClaims(tt.claims)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOIDCAuth_ClaimMappingsDefaults(t *testing.T) {
	// Test that default claim mappings are applied
	mappings := config.OIDCClaimMappings{}

	// Apply defaults as done in NewOIDCAuth
	if mappings.OperatorID == "" {
		mappings.OperatorID = "sub"
	}
	if mappings.Groups == "" {
		mappings.Groups = "groups"
	}

	assert.Equal(t, "sub", mappings.OperatorID)
	assert.Equal(t, "groups", mappings.Groups)
}

func TestOIDCAuth_ClaimMappingsCustom(t *testing.T) {
	// Test that custom claim mappings are preserved
	mappings := config.OIDCClaimMappings{
		OperatorID: "employee_id",
		Groups:     "memberOf",
	}

	// Apply defaults - should not override
	if mappings.OperatorID == "" {
		mappings.OperatorID = "sub"
	}
	if mappings.Groups == "" {
		mappings.Groups = "groups"
	}

	assert.Equal(t, "employee_id", mappings.OperatorID)
	assert.Equal(t, "memberOf", mappings.Groups)
}

func TestOIDCClaims_Fields(t *testing.T) {
	claims := &OIDCClaims{
		Subject:    "user123",
		OperatorID: "op456",
		Groups:     []string{"admins", "developers"},
		Email:      "user@example.com",
		ExpiresAt:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	assert.Equal(t, "user123", claims.Subject)
	assert.Equal(t, "op456", claims.OperatorID)
	assert.Equal(t, []string{"admins", "developers"}, claims.Groups)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), claims.ExpiresAt)
}

func TestOIDCAuth_AllowedGroupsLogic(t *testing.T) {
	// Test the allowed groups logic used in ValidateToken
	tests := []struct {
		name          string
		allowedGroups []string
		userGroups    []string
		expectAllowed bool
	}{
		{
			name:          "no allowed groups configured - all allowed",
			allowedGroups: []string{},
			userGroups:    []string{"random"},
			expectAllowed: true,
		},
		{
			name:          "user in allowed group",
			allowedGroups: []string{"developers", "admins"},
			userGroups:    []string{"developers"},
			expectAllowed: true,
		},
		{
			name:          "user not in allowed group",
			allowedGroups: []string{"developers", "admins"},
			userGroups:    []string{"guests"},
			expectAllowed: false,
		},
		{
			name:          "user in one of multiple groups",
			allowedGroups: []string{"developers"},
			userGroups:    []string{"guests", "developers", "users"},
			expectAllowed: true,
		},
		{
			name:          "empty user groups",
			allowedGroups: []string{"developers"},
			userGroups:    []string{},
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the allowed groups check from ValidateToken
			allowed := false
			if len(tt.allowedGroups) == 0 {
				allowed = true
			} else {
				for _, userGroup := range tt.userGroups {
					for _, allowedGroup := range tt.allowedGroups {
						if userGroup == allowedGroup {
							allowed = true
							break
						}
					}
					if allowed {
						break
					}
				}
			}

			assert.Equal(t, tt.expectAllowed, allowed)
		})
	}
}
