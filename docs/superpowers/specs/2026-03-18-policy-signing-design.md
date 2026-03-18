# Policy File Signing Design

## Summary

Add Ed25519 detached signature support for agentsh policy files, enabling cryptographic proof of authorship and integrity. Signatures live in separate `.sig` files (JSON) alongside policy YAML files. Verification is configurable per-deployment (`enforce`, `warn`, `off`). The design is CA-ready: the format reserves fields for future certificate chain support without requiring it in v1.

## Motivation

Policy files control security-critical behavior: file access, network rules, command restrictions, signal handling, resource limits. The current integrity mechanism (SHA256 manifest) proves a file matches what an admin placed on disk, but cannot prove *who* authored it or protect against a compromised delivery channel.

With watchtower policy distribution on the roadmap, signing becomes essential: agents must verify that policies came from a trusted authority, not a MITM or compromised server.

### Threat Model

1. **Tampered policies on disk** — an attacker modifies a policy after deployment
2. **Untrusted delivery channel** — watchtower (or other transport) delivers policies over a network; signing proves provenance
3. **Auditability** — verifiable chain of who signed what, when, and whether the signing key is still trusted

## Design

### Signature File Format

For a policy file `<name>.yaml`, the detached signature lives at `<name>.yaml.sig` in the same directory.

**Schema (JSON):**

```json
{
  "version": 1,
  "algorithm": "ed25519",
  "key_id": "a1b2c3d4e5f67890",
  "signer": "watchtower-prod",
  "signed_at": "2026-03-18T12:00:00Z",
  "signature": "base64-raw-url-encoded-ed25519-signature",
  "cert_chain": []
}
```

| Field | Description |
|-------|-------------|
| `version` | Schema version, currently `1`. Allows future evolution. |
| `algorithm` | Always `"ed25519"` for v1. Present for forward-compat. |
| `key_id` | Identifies which public key to verify against. Derived deterministically: `hex(SHA256(public_key_bytes))[:16]`. |
| `signer` | Optional human-readable label (e.g., `"watchtower-prod"`). Informational only, not used for verification. |
| `signed_at` | RFC 3339 timestamp of when the signature was produced. Used for audit trails and optional expiry checks. |
| `signature` | Ed25519 signature over the raw bytes of the policy file, base64-raw-url encoded. |
| `cert_chain` | Empty array in v1. Reserved for future CA hierarchy (intermediate certificates). |

**What gets signed:** The exact bytes of the policy YAML file as read from disk. No normalization, no parsing. Ed25519 handles its own internal hashing.

**Why JSON for sig files:** The sig file is machine-produced and machine-consumed. JSON is unambiguous to parse, has no YAML footguns (comments, anchors, aliases), and is the standard for structured metadata in signing systems. The policy stays YAML (human-authored). The sig is JSON (machine-authored).

**Why detached (not inline):** Embedding a signature in YAML requires stripping the signature block before verification, which requires YAML canonicalization — a notoriously unreliable process. Detached signatures sign raw bytes, avoiding this entirely.

### Key Management

**Key types:**

- **Signing key** — Ed25519 private key. Held by the signing authority (admin workstation, watchtower server, CI pipeline). Never distributed to agents.
- **Verification key** — Ed25519 public key. Distributed to every agent as the trust anchor.

**Key ID derivation:**

```
key_id = hex(SHA256(ed25519_public_key_bytes))[:16]
```

Deterministic from the public key. No ambiguity about which key a `key_id` refers to.

**Trust store:**

A directory of trusted public keys (default: `/etc/agentsh/keys/`). Each file contains one key:

```json
{
  "key_id": "a1b2c3d4e5f67890",
  "algorithm": "ed25519",
  "public_key": "base64-encoded-32-byte-public-key",
  "label": "watchtower-prod",
  "trusted_since": "2026-03-18T00:00:00Z",
  "expires_at": "2027-03-18T00:00:00Z"
}
```

The `expires_at` field is optional. If present, the key is rejected after expiry even if still in the trust store — defense-in-depth against forgotten keys.

**Key rotation:** Deploy the new public key to the trust store *before* signing with the new private key. Both old and new keys coexist. The `key_id` in the `.sig` file tells the verifier which key to use. Remove old keys once all policies are re-signed.

### Configuration

```yaml
policies:
  signing:
    trust_store: "/etc/agentsh/keys/"
    mode: "warn"  # "enforce" | "warn" | "off"
```

| Mode | Behavior |
|------|----------|
| `enforce` | Reject policies with missing or invalid signatures. Hard security boundary. |
| `warn` | Verify if `.sig` exists, log warning on failure, load the policy anyway. |
| `off` | Skip signature verification entirely. |

**Relationship to existing manifest:** The SHA256 manifest (`policies.sha256`) becomes redundant when signing is in `enforce` mode. In `warn` or `off` mode, the manifest still provides integrity checking as a fallback. Both mechanisms coexist; no removal needed.

### CLI Commands

**Key generation:**

```bash
agentsh policy keygen --output <dir>
```

- Generates an Ed25519 keypair
- Writes private key to `<dir>/private.key` (mode 0600)
- Writes public key in trust store format to `<dir>/public.key.json`
- Prints the `key_id` to stdout

**Signing:**

```bash
agentsh policy sign <policy-file> --key <private-key-file>
```

- Reads raw bytes of `<policy-file>`
- Signs with the Ed25519 private key
- Writes `<policy-file>.sig` alongside it
- Overwrites existing `.sig` (re-signing after edits)
- Optional: `--output <path>` for custom sig path, `--signer <label>` for the signer field

**Verification:**

```bash
agentsh policy verify <policy-file> [--key-dir <trust-store>]
```

- Reads `<policy-file>` and `<policy-file>.sig`
- Looks up `key_id` in the trust store
- Verifies Ed25519 signature against raw file bytes
- Prints result and exits 0 on valid, non-zero otherwise
- Useful for CI pipelines and manual checks

### Verification at Load Time

When `PolicyManager` loads a policy:

1. Read policy bytes from disk
2. Check `policies.signing.mode` — if `"off"`, skip to step 8
3. Look for `<policy-path>.sig`
4. Parse sig JSON, extract `key_id`
5. Find matching public key in `trust_store` directory
6. Check key expiry if `expires_at` is set
7. Verify Ed25519 signature over raw policy bytes
8. On success: log verification event, proceed with loading
9. On failure:
   - `"enforce"` mode: refuse to load, return error
   - `"warn"` mode: log warning, proceed with loading

### Watchtower Delivery Flow

When watchtower distributes a policy update:

1. Watchtower signs the policy (holds the private key, runs the same signing logic as `agentsh policy sign`)
2. Delivers both files: `<policy>.yaml` + `<policy>.yaml.sig`
3. Agent writes both to a **staging directory** (`/etc/agentsh/policies/.staging/`) — not directly into the live policy dir
4. Agent verifies the signature against its trust store
5. **On success:** atomically moves both files into the live policy directory, logs the update
6. **On failure:** rejects the update, logs the failure with details (unknown key, bad signature, missing sig), keeps existing policy
7. The existing `reload_interval` timer picks up the new policy — or watchtower triggers an immediate reload

**Why staging:** The agent never loads an unverified policy, even transiently. Writing directly to the policy dir risks a race where the policy manager reads the new YAML before the `.sig` arrives.

**Trust bootstrapping:** The trust store must be provisioned during agent installation. The watchtower server's public key is part of the agent's initial configuration.

### Audit Trail

Every signature verification produces an audit event:

```json
{
  "event": "policy.signature.verified",
  "policy": "agent-sandbox",
  "key_id": "a1b2c3d4e5f67890",
  "signer": "watchtower-prod",
  "signed_at": "2026-03-18T12:00:00Z",
  "verified_at": "2026-03-18T12:05:00Z",
  "result": "valid"
}
```

Failure events include the reason: `"invalid_signature"`, `"unknown_key"`, `"missing_signature"`, `"expired_key"`.

This integrates with the existing audit system — `PolicyVersion()` can incorporate `key_id` and `signed_at` to detect re-signing events, not just content changes.

### Key Revocation

**V1 (simple):** Remove the public key file from the trust store. On next policy load, policies signed with that key fail with `"unknown_key"`.

**Key expiry (optional):** The `expires_at` field provides time-based revocation. A forgotten key eventually stops being trusted without manual intervention.

**Future:** V2 could add CRL or OCSP-like mechanisms if the CA hierarchy is implemented.

### Future: CA Hierarchy

The format is designed to support this without breaking changes:

- `cert_chain` in the sig file would contain intermediate certificates
- Trust store would hold root CA public keys
- Verification would walk the chain: sig → intermediate → root
- V1 requires `cert_chain` to be empty; v2 adds chain validation logic

No work needed now — the extension points are in place.

## Testing Strategy

- Unit tests for signing and verification (valid, tampered, wrong key, expired key, missing sig)
- Unit tests for trust store loading and key lookup
- Integration tests for policy manager verification at load time (all three modes)
- Integration tests for the CLI commands (keygen, sign, verify)
- Test key rotation scenario (two keys in trust store, sign with new, verify both)

## Dependencies

- `crypto/ed25519` (Go stdlib) — signing and verification
- `crypto/sha256` (Go stdlib) — key ID derivation
- `encoding/json` (Go stdlib) — sig file and trust store parsing
- No external dependencies required
