// Package secretstest provides test doubles for the
// secrets.SecretProvider interface.
//
// MemoryProvider is an in-memory fake that serves a fixed (but
// mutable) map of secrets keyed by the canonical URI form of the
// SecretRef. Tests construct one with a seed map, optionally add
// or remove entries during the test, and pass it where a real
// provider would go.
//
// ProviderContract runs the same baseline behavioral assertions
// against any SecretProvider. Provider implementations call it
// from their own test files to verify they honor the interface
// contract.
//
// # Production code MUST NOT import this package.
//
// The package name mirrors stdlib conventions like httptest and
// iotest. It ships under internal/proxy/secrets/ so the keyring
// package (and future provider packages) can import it from their
// _test.go files without going through the module boundary.
package secretstest
