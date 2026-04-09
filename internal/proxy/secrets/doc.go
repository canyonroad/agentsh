// Package secrets defines the SecretProvider interface that agentsh
// uses to fetch real credentials from external secret stores at
// session start, plus the URI grammar and sentinel errors shared by
// all provider implementations.
//
// Provider implementations live in subpackages, one per backend:
//
//   - internal/proxy/secrets/keyring — OS keyring (Keychain / Secret
//     Service / Credential Manager) via github.com/zalando/go-keyring.
//
// Future plans add vault, awssm, gcpsm, azurekv, and op subpackages.
// Every provider imports this package for the interface and types;
// this package imports none of them.
//
// Test doubles live in the sibling secretstest package. Production
// code must not import secretstest.
//
// The design is documented in
// docs/superpowers/specs/2026-04-08-plan-03-secret-provider-keyring-design.md
// and the parent migration spec
// docs/superpowers/specs/2026-04-07-external-secrets-design.md.
package secrets
