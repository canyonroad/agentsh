package vault

import (
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestConfig_TypeName(t *testing.T) {
	c := Config{}
	if got := c.TypeName(); got != "vault" {
		t.Errorf("TypeName() = %q, want 'vault'", got)
	}
}

func TestConfig_Dependencies_TokenLiteral(t *testing.T) {
	c := Config{Auth: AuthConfig{Method: "token", Token: "literal"}}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty", deps)
	}
}

func TestConfig_Dependencies_TokenRef(t *testing.T) {
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	c := Config{Auth: AuthConfig{Method: "token", TokenRef: &tokenRef}}
	deps := c.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() length = %d, want 1", len(deps))
	}
	if deps[0].Scheme != tokenRef.Scheme || deps[0].Host != tokenRef.Host || deps[0].Path != tokenRef.Path {
		t.Errorf("Dependencies()[0] = {%s, %s, %s}, want {%s, %s, %s}",
			deps[0].Scheme, deps[0].Host, deps[0].Path,
			tokenRef.Scheme, tokenRef.Host, tokenRef.Path)
	}
}

func TestConfig_Dependencies_AppRole(t *testing.T) {
	roleRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-role"}
	secretRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-secret"}

	c := Config{
		Auth: AuthConfig{
			Method:      "approle",
			RoleIDRef:   &roleRef,
			SecretIDRef: &secretRef,
		},
	}
	deps := c.Dependencies()
	if len(deps) != 2 {
		t.Fatalf("Dependencies() length = %d, want 2", len(deps))
	}
}

func TestConfig_Dependencies_AppRoleIgnoresTokenRef(t *testing.T) {
	// TokenRef should be ignored for approle method.
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	roleRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-role"}

	c := Config{
		Auth: AuthConfig{
			Method:    "approle",
			RoleIDRef: &roleRef,
			TokenRef:  &tokenRef, // irrelevant for approle
		},
	}
	deps := c.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("Dependencies() length = %d, want 1 (only RoleIDRef)", len(deps))
	}
}

func TestConfig_Dependencies_Kubernetes(t *testing.T) {
	// Kubernetes uses a service account token file, no chained refs.
	c := Config{Auth: AuthConfig{Method: "kubernetes", KubeRole: "my-role"}}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty", deps)
	}
}

func TestConfig_Dependencies_LiteralOverridesRef(t *testing.T) {
	// When both literal and ref are set, the ref is not declared as a
	// dependency. The constructor will reject the config later.
	tokenRef := secrets.SecretRef{Scheme: "keyring", Host: "agentsh", Path: "vault-token"}
	c := Config{
		Auth: AuthConfig{
			Method:   "token",
			Token:    "literal-value",
			TokenRef: &tokenRef,
		},
	}
	if deps := c.Dependencies(); len(deps) != 0 {
		t.Errorf("Dependencies() = %v, want empty when literal is set", deps)
	}
}
