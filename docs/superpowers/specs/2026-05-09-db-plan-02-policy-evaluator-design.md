# db-access Plan 02 — Policy Evaluator (design)

Status: design approved 2026-05-09. Implementation plan to follow via writing-plans.

Cross-references:
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 02.
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §9 (policy schema), §10 (decision semantics), §23.3 (evaluator tests).
- Predecessor: Plan 01 (`internal/db/effects`, `internal/db/events`, `internal/db/service` already shipped).

This document captures the package-shape and interface decisions that the spec leaves to the implementer. The §10.2 algorithm is fully specified upstream and is not re-derived here.

## 1. Scope

In scope:

- `internal/db/policy/` package: `RuleSet`, `StatementRule`, `ConnectionRule`, `Decision`, `ApprovalRequest`, `Decode`, `Evaluate`, `EvaluateConnection`.
- Glob compilation, alias expansion, message-template precompilation.
- §9.4 config-load validation: errors + warnings.
- Three `yaml.Node` fields added to `internal/policy.Policy` so YAML files referencing the DB rule families parse without error.
- `internal/db/policy/testdata/sample-policy.yaml` — the §9.2 example, source of truth for Plan 03's golden corpus.
- Test suite covering every §23.3 category plus R14 order-independence.

Out of scope (deferred to later plans):

- Statement-text redaction *operation* (Plan 03 — needs AST). Plan 02 owns only the config field and its default.
- Approval workflow plumbing (Plan 04+).
- DBEvent emission (Plan 04+).
- Cancel mapping (Plan 06).
- Catalog-aware resolution (Phase 2+).

## 2. Architectural decisions

These six decisions were settled during brainstorming and govern the rest of the design.

**D1. Self-contained subpackage with thin hook.** All DB rule schema, evaluation logic, and validation lives in `internal/db/policy/`. `internal/policy` gets three new `yaml.Node` fields and nothing else. No reverse import. Matches the existing `Providers map[string]yaml.Node` precedent in `internal/policy/model.go:46`.

**D2. Glob library.** `gobwas/glob` (already a project dependency, used across `internal/policy`). Compile patterns once at policy load; never compile on the evaluation hot path.

**D3. Compilation pattern.** Explicit `Compile`-style step inside `Decode`, mirroring `internal/policy/http_service_compile.go`. Operators interact with the on-disk struct shapes; the evaluator runs against precompiled internal forms.

**D4. `Decision` lives in `internal/db/policy`.** `internal/db/events` imports it for the Plan 04 `DBEvent.decision` wiring. Dependency arrow points from "audit record shape" → "logic that decides" — natural.

**D5. Slim `Decision` + sibling `ApprovalRequest`.** Plan 02 does not couple to runtime approval mechanics. When `Decision.Verb == Approve`, `Decision.Approval` is non-nil and carries `Timeout` and `ContributingApproveRules`. Plan 04 wires this into the actual approval channel.

**D6. yaml.Node fields + db-side `Decode`.** `internal/policy.Policy` stores raw YAML for the three DB rule families. `dbpolicy.Decode(*policy.Policy) (*RuleSet, []Warning, error)` decodes and validates. No reverse import; matches the `Providers` pattern.

## 3. Package layout

```
internal/db/policy/
├── types.go            # public types: StatementRule, ConnectionRule, DBService,
│                       # RuleSet, Decision, ApprovalRequest, Warning, enums
├── decode.go           # Decode(*policy.Policy) (*RuleSet, []Warning, error)
├── compile.go          # internal: glob compile, alias expand, message templates,
│                       # compiledStatementRule, compiledConnectionRule
├── validate.go         # §9.4 errors + warnings; pure function over decoded shapes
├── evaluate.go         # Evaluate(stmt, rs, svc) Decision
├── evaluate_conn.go    # EvaluateConnection(info, rs) Decision
├── redaction.go        # RedactionConfig type + parsing of policies.db block
├── sample.go           # //go:embed testdata/sample-policy.yaml; MustLoadSample
├── testdata/
│   └── sample-policy.yaml
└── *_test.go           # one file per §23.3 category (see §6)
```

Build tags: none. Package compiles on every platform. CI runs `go test ./internal/db/policy/...` on Linux + macOS and `GOOS=windows go build ./...` per `CLAUDE.md`.

## 4. Public types

```go
type ServiceID string

type DecisionVerb uint8
const (
    VerbAllow DecisionVerb = iota
    VerbAudit
    VerbApprove
    VerbDeny
)

// Implicit-deny is *not* a separate verb. It is encoded as Verb == VerbDeny
// with RuleName == "" and a stock Reason ("no rule covers ..."). This matches
// the §8 DBEvent wire schema (decision.verb ∈ {allow, deny, approve, audit})
// while still letting tests assert on the distinction via RuleName.

type RuleKind uint8
const (
    RuleKindStatement RuleKind = iota
    RuleKindConnection
    RuleKindCancel
)

type ConnectionMatchKind uint8
const (
    MatchConnect ConnectionMatchKind = iota
    MatchCancel
    MatchReplication
)

type DBService struct {
    Name                      string
    Family                    string
    Dialect                   string
    Upstream                  string
    TLSMode                   string
    DenyModeInTx              string
    AllowFunctionCallProtocol bool
    AllowGSSEncryption        bool
    TrustedNetwork            bool
}

type StatementRule struct {
    Name                        string
    DBService                   string
    DBFamily                    string
    DBDialect                   string
    Schemas                     []string
    Objects                     []string
    Operations                  []string
    Subtypes                    []string
    MatchObjectResolution       string
    Decision                    string
    Message                     string
    Timeout                     time.Duration
    AcknowledgeAuditOnDangerous bool
}

type ConnectionRule struct {
    Name            string
    DBService       string
    MatchKind       string
    DBUser          []string
    Database        string
    ApplicationName string
    ClientIdentity  string
    Decision        string
    Message         string
    Timeout         time.Duration
}

type ConnectionInfo struct {
    Service         ServiceID
    MatchKind       ConnectionMatchKind
    DBUser          string
    Database        string
    ApplicationName string
    ClientIdentity  string
}

type Decision struct {
    Verb                   DecisionVerb
    RuleKind               RuleKind
    RuleName               string
    MatchingEffectIndex    int          // -1 for connection-level decisions
    MatchingEffectGroup    effects.Group
    Reason                 string
    ContributingAuditRules []string     // populated only when Verb == VerbApprove
    Approval               *ApprovalRequest
}

type ApprovalRequest struct {
    Timeout                  time.Duration
    ContributingApproveRules []string
}

type Warning struct {
    Rule    string
    Field   string
    Code    string
    Message string
    Line    int
}

type RedactionConfig struct {
    LogStatements              Redaction // none | parameters_redacted | full
    ApprovalStatementPreview   Redaction
    ApprovalStatementChars     int       // default 200
}

type RuleSet struct {
    // unexported fields; use Decode and the Evaluate functions
}
```

Public functions:

```go
func Decode(p *policy.Policy) (*RuleSet, []Warning, error)
func Evaluate(stmt effects.ClassifiedStatement, rs *RuleSet, svc ServiceID) Decision
func EvaluateConnection(info ConnectionInfo, rs *RuleSet) Decision
func MustLoadSample() *RuleSet  // for Plan 03 corpus tests
func (rs *RuleSet) Redaction() RedactionConfig
func (rs *RuleSet) Service(id ServiceID) (DBService, bool)
```

## 5. Compilation pipeline

`Decode` runs three phases. Failures abort with an error wrapping the offending YAML position (yaml.v3 nodes carry line numbers).

**Phase A — Decode.** Each `yaml.Node` field on `policy.Policy` is decoded with `KnownFields(true)` into the typed structs above. Yaml decode errors surface as-is.

**Phase B — Validate.** `validate(svcs, stmt, conn)` walks the decoded shapes. Errors are accumulated and returned via `errors.Join`; operators see all problems per load. Warnings accumulate into a `[]Warning` returned alongside the result. See §6 for the full rule list.

**Phase C — Compile.** Builds the internal `RuleSet`. Per rule:

- Glob-compile every `objects` and `schemas` pattern via `gobwas/glob`.
- Alias-expand `operations` via `effects.ExpandAlias`. The compiled rule holds `map[effects.Group]struct{}` for O(1) match.
- Parse `message` as a `text/template.Template` with the `{{.Operation}}, {{.Subtype}}, {{.Schema}}, {{.Object}}, {{.Verb}}, {{.StatementPreview}}` field set.
- Resolve `db_service` to its `DBService` once; store the resolved pointer (or nil for unscoped rules).

Compile is one-shot at load. Hot-path evaluation is map lookups and pre-compiled glob `Match` calls — no allocation beyond the result `Decision`.

**Reload posture.** `RuleSet` is immutable after `Decode` (no exported mutating methods). Plan 04's proxy holds a `*RuleSet` pointer and swaps it atomically on policy reload. Plan 02 ships no reload coordination logic.

## 6. Validation (§9.4)

**Errors (load aborts):**

| Code | Trigger |
|------|---------|
| `service_unknown_tls_mode` | `DBService.TLSMode` not in {passthrough, terminate_reissue, terminate_plaintext_upstream} |
| `service_tls_mode_required` | `DBService.TLSMode` empty (no default per §9.1) |
| `service_plaintext_unsafe_dest` | `terminate_plaintext_upstream` to non-RFC1918, non-loopback dest without `trusted_network: true` |
| `rule_service_passthrough` | Statement rule references service whose `tls_mode == passthrough` |
| `rule_service_unknown` | Rule references nonexistent `db_service` |
| `conn_passthrough_field_unavailable` | Connection rule under passthrough service references `db_user`/`database`/`application_name` |
| `rule_decision_redirect` | `decision: redirect` (Phase 2 only) |
| `rule_unknown_subtype` | `subtypes` references a token `effects.ParseSubtype` rejects |
| `rule_unknown_operation` | `operations` token `effects.ExpandAlias` rejects |
| `rule_too_broad_allow` | No `db_service` AND no `db_family` AND `decision: allow` AND `operations: ["*"]` |
| `cancel_rule_approve` | `match_kind: cancel` with `decision: approve` |
| `approve_timeout_exceeds_max` | Approve rule timeout > 600s hard cap (Phase 1) |
| `glob_compile` | Any `objects`/`schemas`/`application_name`/`client_identity` pattern fails to compile |
| `message_template_parse` | `message` template fails to parse |

**Warnings (load proceeds):**

| Code | Trigger |
|------|---------|
| `audit_on_dangerous` | `decision: audit` paired with operations resolving to risk tier ≥ high. Silenced by `acknowledge_audit_on_dangerous: true` |
| `approve_on_replication` | `decision: approve` on `match_kind: replication`. Replication is default-deny (§11.1); approve-replication is unusual but not nonsensical |

`Warning` carries the YAML line number (from the originating `yaml.Node`) so operators see IDE-friendly errors.

## 7. Evaluate algorithm (statement)

Direct implementation of §10.2. Pseudocode:

```
Evaluate(stmt, rs, svc):
  applicable = rs.statementRulesFor(svc)        # global + per-service
  perEffect  = []effectDecision
  for i, e in stmt.Effects:
    perEffect[i] = evaluateEffect(e, applicable)
  return foldEffects(stmt, perEffect)

evaluateEffect(e, applicable):
  # Pass 1: deny
  for r in applicable where r.decision == deny:
    if r matches e.group/subtype/resolution:
      for o in e.objects:
        if r.objects matches o (or r.objects empty):
          return effectDecision{verb: deny, rule: r.name, object: o}

  # Pass 2: coverage
  coverage = map[object][]rule
  for o in e.objects:
    for r in applicable where r.decision in {allow, audit, approve}:
      if r matches e.group/subtype/resolution:
        if r.objects matches o (or r.objects empty):
          coverage[o] = append(coverage[o], r)

  if any object o in e.objects has empty coverage:
    return effectDecision{verb: implicit_deny, object: o}

  # Pass 3: per-effect verb is most-restrictive among covering rules
  verb = allow
  primary = first allow rule
  contributingAudit = []
  contributingApprove = []
  for r in flatten(coverage):
    if r.decision == approve: verb = max(verb, approve); contributingApprove += r
    if r.decision == audit:   verb = max(verb, audit);   contributingAudit += r
  if verb == approve: primary = first approve rule by policy file order
  elif verb == audit:  primary = first audit rule by policy file order
  return effectDecision{verb, rule: primary.name, contributingAudit, contributingApprove}

foldEffects(stmt, perEffect):
  # effectDecision.verb is an internal enum that includes implicit_deny;
  # the fold normalizes it to the public DecisionVerb (no VerbImplicitDeny).
  pick effect e* with most-restrictive verb (deny ≡ implicit_deny > approve > audit > allow)
  on tie among non-implicit-deny: lowest index wins
  on tie between explicit deny and implicit deny: explicit deny wins (so RuleName is non-empty whenever possible)
  Decision{
    Verb: e*.verb,
    RuleKind: Statement,
    RuleName: e*.rule (or "" for implicit_deny),
    MatchingEffectIndex: index of e*,
    MatchingEffectGroup: stmt.Effects[i].Group,
    Reason: render(e*.rule.msgTemplate, stmt) or stockImplicitDenyMessage(e*),
    ContributingAuditRules: e*.contributingAudit (only if final verb == approve),
    Approval: nil unless final verb == approve, then ApprovalRequest{
      Timeout: min(r.timeout for r in contributingApprove),  # shortest wins (D-OQ2)
      ContributingApproveRules: e*.contributingApprove,
    },
  }
```

**Tiebreak resolutions** (chosen for determinism, locked during brainstorm):

- `MatchingEffectIndex`: lowest index on tie.
- `RuleName` for audit/approve: first rule by **policy file order** (D-OQ3).
- `ApprovalRequest.Timeout`: `min` across contributing approve rules (D-OQ2 — most-restrictive principle applied to time).
- Implicit deny: encoded as `Verb == VerbDeny`, `RuleName == ""`, `Reason == "no rule covers <object> in <group> effect"`. Plan 04 emits this as `decision.verb: "deny"` per §8.

## 8. Evaluate algorithm (connection)

Connection rules have no object-coverage notion; each rule either matches or doesn't.

```
EvaluateConnection(info, rs):
  applicable = rs.connection where r.match_kind == info.MatchKind
                              AND (r.db_service == info.Service OR r.db_service == "")
  matched = []
  for r in applicable:
    if r.db_user non-empty AND info.DBUser not in r.db_user: skip
    if r.database non-empty AND info.Database != r.database: skip
    if r.application_name non-empty AND not r.application_name.Match(info.ApplicationName): skip
    if r.client_identity non-empty AND not r.client_identity.Match(info.ClientIdentity): skip
    matched += r

  if matched empty:
    return Decision{Verb: VerbDeny, RuleName: "",
                    RuleKind: kindFor(info.MatchKind), MatchingEffectIndex: -1,
                    Reason: "no connection rule matched"}

  # Pick most-restrictive: deny > approve > audit > allow
  pick r* = most-restrictive in matched, ties broken by policy file order
  return Decision{
    Verb: r*.decision,
    RuleKind: kindFor(info.MatchKind),
    RuleName: r*.name,
    MatchingEffectIndex: -1,
    MatchingEffectGroup: GroupUnknown,
    Reason: render(r*.message_template),
    Approval: nil unless r*.decision == approve,
  }
```

`kindFor(Cancel) == RuleKindCancel`; `kindFor(Connect) == RuleKindConnection`. Cancel-rule-with-approve has already been rejected at config-load (`cancel_rule_approve` error), so `EvaluateConnection` does not handle that combination.

## 9. Sample policy and tests (§23.3)

**Sample policy: `internal/db/policy/testdata/sample-policy.yaml`.** Exact contents of the §9.2 example. Embedded via `//go:embed`; `MustLoadSample()` returns a `*RuleSet`.

The roadmap's "corpus/sample-policy.yaml" is a logical name. Plan 03's corpus tests load the sample via `dbpolicy.MustLoadSample()`, not via filesystem path. This keeps the file co-located with the package that owns its semantics (per §4 cross-cutting decisions: "Modifying the sample policy is a Plan 02 change").

**Test files:**

| File | §23.3 category |
|------|----------------|
| `evaluate_coverage_test.go` | Strict object coverage (allow / audit / approve cases) |
| `evaluate_implicit_deny_test.go` | Implicit deny on uncovered objects |
| `evaluate_audit_coverage_test.go` | Audit as coverage (forward + tag) |
| `evaluate_approve_scope_test.go` | Approve does not extend coverage to unrelated objects |
| `evaluate_deny_precedence_test.go` | Deny precedence over allow / audit / approve |
| `evaluate_resolution_test.go` | `match_object_resolution` per-effect |
| `evaluate_multi_effect_test.go` | Multi-effect statements with mixed decisions |
| `evaluate_primary_ordering_test.go` | Risk-tier-first primary effect ordering (uses `effects.Order`) |
| `evaluate_order_independence_test.go` | R14 — randomized rule reordering, identical outcome |
| `evaluate_conn_test.go` | Connection-rule evaluation; passthrough constraints |
| `validate_test.go` | One subtest per error/warning code in §6 |
| `decode_test.go` | YAML round-trip via `Providers`-style yaml.Node fields |
| `sample_test.go` | The 14 §10.2 worked examples as a single table |

**Order-independence test (R14).** Take each §10.2 example, generate N random permutations of the rule list (seeded RNG), assert all permutations produce the same `Decision`. Catches accidental reliance on slice order in `evaluateEffect`.

## 10. Cross-cutting decisions resolved during brainstorming

For posterity:

- **D-OQ1 — Reload coordination.** Out of scope. `RuleSet` is immutable; Plan 04 swaps pointers.
- **D-OQ2 — Approve timeout source-of-truth.** Shortest timeout wins across contributing approve rules. Most-restrictive principle applied to time.
- **D-OQ3 — Audit/approve `RuleName` tie-break.** First rule by policy file order. Order-independence applies to outcomes, not to which rule's name lands in the audit record.

## 11. Acceptance criteria

Plan 02 is done when:

1. `go test ./internal/db/policy/...` passes on Linux and macOS.
2. `GOOS=windows go build ./...` passes.
3. `internal/policy/load.go` accepts a YAML file containing `db_services`, `database_rules`, and `database_connection_rules` without error (existing tests still pass).
4. `MustLoadSample()` returns a non-nil `*RuleSet` whose `Evaluate` produces the §10.2 worked-examples table verbatim.
5. Every error code and warning code in §6 has a passing subtest in `validate_test.go`.
6. R14 order-independence test passes with at least 8 permutations per example, seeded.
7. Hot-path allocation budget: `Evaluate` may allocate the per-call `coverage` map, the `perEffect` slice, and the result `Decision` plus its slices. It MUST NOT compile globs, parse templates, or expand aliases on the hot path — those are precompile artifacts. Verified by a `go test -bench` smoke check that compares allocations against a fixed budget.

## 12. Out of scope reminder

Plan 02 produces *types and pure functions only*. It does not emit events, hold approvals, redact statement text, or talk to the wire. Those belong to Plans 03–07.
