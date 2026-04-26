package ocsf

import (
	"strings"
	"testing"
)

// sensitiveKeys is the test-only fixture of key names that MUST NOT
// appear in any FieldRule.Key across the entire registry. This is a
// guard against accidental allowlisting of values that would carry
// secrets to Watchtower.
//
// The list is intentionally lowercase; the check is case-insensitive.
// Matches are exact (a registered key "x_authorization" does NOT match
// "authorization"); to widen, add the variant explicitly.
var sensitiveKeys = []string{
	"authorization",
	"cookie",
	"set-cookie",
	"set_cookie",
	"proxy-authorization",
	"proxy_authorization",
	"api_key",
	"api-key",
	"apikey",
	"secret",
	"password",
	"passwd",
	"token",
	"bearer",
	"x-auth-token",
	"x_auth_token",
	"private_key",
	"client_secret",
}

func TestRegistry_NoSensitiveKeysAllowlisted(t *testing.T) {
	deny := make(map[string]struct{}, len(sensitiveKeys))
	for _, k := range sensitiveKeys {
		deny[strings.ToLower(k)] = struct{}{}
	}
	for evType, mapping := range registry {
		for _, rule := range mapping.FieldsAllowlist {
			if _, banned := deny[strings.ToLower(rule.Key)]; banned {
				t.Errorf("registry[%q] allowlists sensitive key %q — must be omitted entirely",
					evType, rule.Key)
			}
		}
	}
}
