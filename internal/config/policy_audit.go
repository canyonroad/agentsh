package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// PolicyVersion computes a version hash for policy content.
func PolicyVersion(content []byte) string {
	h := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(h[:8]) // Short hash for readability
}

// PolicyDiff computes a summary of changes between policies.
func PolicyDiff(oldPolicy, newPolicy *PolicyFiles) string {
	var added, removed, modified int

	// Compare file policy rules
	if oldPolicy != nil && newPolicy != nil {
		if oldPolicy.File != nil && newPolicy.File != nil {
			oldRules := len(oldPolicy.File.Rules)
			newRules := len(newPolicy.File.Rules)
			if newRules > oldRules {
				added += newRules - oldRules
			} else if oldRules > newRules {
				removed += oldRules - newRules
			}
			modified = min(oldRules, newRules)
		}

		// Similar for network rules
		if oldPolicy.Network != nil && newPolicy.Network != nil {
			oldRules := len(oldPolicy.Network.Rules)
			newRules := len(newPolicy.Network.Rules)
			if newRules > oldRules {
				added += newRules - oldRules
			} else if oldRules > newRules {
				removed += oldRules - newRules
			}
		}

		// DNS rules
		if oldPolicy.DNS != nil && newPolicy.DNS != nil {
			oldRules := len(oldPolicy.DNS.Rules)
			newRules := len(newPolicy.DNS.Rules)
			if newRules > oldRules {
				added += newRules - oldRules
			} else if oldRules > newRules {
				removed += oldRules - newRules
			}
		}

		// Registry rules (Windows)
		if oldPolicy.Registry != nil && newPolicy.Registry != nil {
			oldRules := len(oldPolicy.Registry.Rules)
			newRules := len(newPolicy.Registry.Rules)
			if newRules > oldRules {
				added += newRules - oldRules
			} else if oldRules > newRules {
				removed += oldRules - newRules
			}
		}
	}

	if added == 0 && removed == 0 && modified == 0 {
		return "no changes detected"
	}

	return fmt.Sprintf("+%d rules, -%d rules, ~%d checked", added, removed, modified)
}
