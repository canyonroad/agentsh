# Skilliks Phase 5: Signing, Transparency & Verify Design

## Database Schema

Schema enforces that pending rows have no rekor_* values and completed rows have all of them.

## Queries

- CompleteProvenanceRecord: UPDATE sets all rekor fields and status='completed' where status='pending'. 
  Zero rows means either concurrent completion or missing reservation. 
  On zero rows, follow-up read of status for same (skill_version_id, predicate_type) is required: 
  if status='completed', concurrent completion is success; if missing or other state, non-retryable error (invariant violation).

## Publication Workflow

Mark complete via CompleteProvenanceRecord. On zero-row return, perform follow-up read to confirm concurrent completion (status='completed' is success) or detect missing reservation (error).

## Trust-Root Configuration

When SKILLIKS_SIGNER is local or gcpkms and SKILLIKS_REKOR_URL is non-empty:
- Local mode: public key derived from SKILLIKS_SIGNER_PRIVATE_KEY_PATH if SKILLIKS_SIGNER_PUBLIC_KEY_PEM unset.
- GCPkms mode: SKILLIKS_SIGNER_PUBLIC_KEY_PEM is required only when SKILLIKS_REKOR_URL is non-empty. Phase 5 does not add separate KMS public-key lookup.

## Configuration

SKILLIKS_SIGNER_KID: required when local or gcpkms
SKILLIKS_SIGNER_PUBLIC_KEY_PEM: optional when local; required when gcpkms and SKILLIKS_REKOR_URL is non-empty
SKILLIKS_REKOR_URL: empty = worker no-ops+audits, trust-root returns 503

In gcpkms builds with SKILLIKS_REKOR_URL set (configured mode), startup fails fast if SKILLIKS_SIGNER_PUBLIC_KEY_PEM is missing.
When SKILLIKS_REKOR_URL is empty, gcpkms builds do not require the PEM and proceed with no-op worker behavior.

## Testing

Config/build tests: reject gcpkms without SKILLIKS_SIGNER_PUBLIC_KEY_PEM when SKILLIKS_REKOR_URL non-empty; permit missing PEM when SKILLIKS_REKOR_URL empty.

## Summary

Phase 5 adds provenance signing and transparency log integration. Design enforces strong invariants via table CHECK, scopes configuration requirements to modes using them, clarifies concurrent completion vs missing reservation semantics via follow-up reads.
