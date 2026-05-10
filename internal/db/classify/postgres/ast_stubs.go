// Package postgres — ast_stubs.go contains no-op handler stubs for SQL
// families whose real implementation hasn't landed yet. Each stub writes a
// single GroupUnknown effect and a "not yet implemented" Error so the
// dispatcher's "always one effect" invariant holds. As real handlers ship in
// Tasks 6–13, the matching stub is deleted from this file.
package postgres

// All Task-12 stubs (call/do/maintenance/reindex/cluster/checkpoint/lock/
// notify) have been replaced by the real handlers in ast_misc.go. This file
// is intentionally retained as a placeholder for future stubs and so that
// `stub` (if reintroduced) lives in one place.
