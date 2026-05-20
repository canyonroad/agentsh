# DB Require WHERE Policy Design

**Status:** Draft approved in brainstorming on 2026-05-20.
**Owner:** Canyon Road
**Source context:** `docs/agentsh-db-access-spec.md`, DB statement policy evaluator, Postgres classifier.

## 1. Purpose

AgentSH database policies can scope statement decisions by service, operation group, object selectors, resolution confidence, and decision verb. They cannot currently express "this mutation is allowed only when the SQL statement contains a `WHERE` clause."

This feature adds a small, syntactic guard for Postgres-family `UPDATE` and `DELETE` statements:

```yaml
database_rules:
  - name: allow-scoped-user-mutations
    db_service: appdb
    operations: [modify, delete]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    require_where: true
    decision: allow
```

The intent is to prevent accidental full-table mutations when an allow, audit, approve, or redirect-like future rule would otherwise cover the mutation effect. This is not row-level predicate analysis. `WHERE true` satisfies the first version because the guard checks for a syntactic top-level `WHERE` clause only.

## 2. Scope

### In Scope

- Add `require_where: true` to `database_rules`.
- Support Postgres-family top-level `UPDATE` and `DELETE` statements.
- Preserve the existing per-effect coverage model: a rule with `require_where: true` does not cover a mutation effect unless the classifier observed a `WHERE` clause.
- Fail closed naturally through existing implicit-deny behavior when no rule covers the mutation effect.
- Reject misleading configs where `require_where` is paired with operation groups outside `modify` and `delete`.
- Document the feature in the DB access spec and policy skill schema references.

### Out of Scope

- Proving predicate selectivity or safety.
- Rejecting tautologies such as `WHERE true`.
- Requiring tenant predicates, primary-key predicates, row limits, or parameterized predicates.
- Supporting `SELECT`, DDL, session, transaction, COPY, procedural, or unknown statement groups.
- Supporting non-Postgres dialects in the first implementation.
- Changing the meaning of existing policies that do not set `require_where`.

## 3. Policy Semantics

`require_where` is a statement-rule matcher. It is not a new decision verb and not a special deny path.

A statement rule with `require_where: true` can match a `modify` or `delete` effect only when that effect carries classifier metadata saying the top-level statement has a `WHERE` clause.

Examples:

- `UPDATE public.users SET disabled = true WHERE id = 123` has a top-level `WHERE`, so a matching `require_where: true` rule can cover the `modify` effect.
- `UPDATE public.users SET disabled = true` has no top-level `WHERE`, so that rule does not cover the `modify` effect.
- `DELETE FROM public.users WHERE disabled = true` has a top-level `WHERE`, so the rule can cover the `delete` effect.
- `DELETE FROM public.users` has no top-level `WHERE`, so the rule does not cover the `delete` effect.

If another rule without `require_where` covers the same mutation effect, the existing evaluator semantics still apply. Operators who want a strict guard must ensure their mutation allow/approve/audit coverage rules for the sensitive object also require `WHERE`, or add explicit deny rules for broader cases.

## 4. Implementation Shape

### Effects Model

Add observed statement-shape metadata to the classified effect:

```go
type Effect struct {
    Group    Group
    Subtype  Subtype
    Objects  []ObjectRef
    HasWhere bool `json:"has_where,omitempty"`
    // existing fields...
}
```

`HasWhere` describes the SQL shape observed by the classifier. It must not be named as if it were a policy requirement.

### Postgres Classifier

Set `HasWhere` on the primary mutation effect:

- `classifyUpdate`: `HasWhere: s.WhereClause != nil`
- `classifyDelete`: `HasWhere: s.WhereClause != nil`

Do not propagate `HasWhere` to secondary read effects, CTE effects, COPY effects, or function-escalation effects. Data-modifying CTEs should keep their own classification behavior through the existing nested statement classification path.

### Policy Decode And Compile

Add the on-disk field:

```go
RequireWhere bool `yaml:"require_where,omitempty"`
```

Compile it onto `compiledStatementRule`.

Extend `ruleMatchesEffectMeta` so:

- if `require_where` is false, existing behavior is unchanged;
- if `require_where` is true and the effect group is `modify` or `delete`, the rule matches only when `e.HasWhere` is true;
- validation should prevent `require_where` from reaching unsupported groups.

### Validation

Validation should reject `require_where: true` unless the expanded operation group set is non-empty and every group is one of:

- `modify`
- `delete`

This means mixed or broad aliases are rejected when they expand outside the supported set, including:

- `operations: [read]`
- `operations: ["*"]`
- `operations: [read, delete]`
- `operations: [MUTATE]` if `MUTATE` expands beyond `modify` and `delete`

Use a stable error code such as `rule_require_where_invalid_operation`.

## 5. Testing

Add focused coverage at the same layers as the existing DB policy work:

- Validation accepts `require_where: true` for `operations: [modify]`, `[delete]`, and `[modify, delete]`.
- Validation rejects unsupported operation sets with `rule_require_where_invalid_operation`.
- Postgres classifier marks `UPDATE ... WHERE ...` and `DELETE ... WHERE ...` mutation effects with `HasWhere`.
- Postgres classifier leaves `UPDATE ...` and `DELETE ...` mutation effects without `HasWhere`.
- Policy evaluator allows a covered mutation with `WHERE` when the only covering allow rule has `require_where: true`.
- Policy evaluator denies the same mutation without `WHERE` through implicit coverage failure.
- Simple Query proxy integration denies a no-`WHERE` mutation before forwarding when the only matching mutation allow rule requires `WHERE`.

Regression tests should include a rule with the same object selector and `require_where: true` to prove that object coverage alone does not bypass the shape guard.

## 6. Documentation Updates

Update these surfaces:

- `docs/agentsh-db-access-spec.md`: add `require_where` to the `database_rules` field table and statement matching semantics.
- `docs/operations/policies.md`: add an operator example for sensitive table mutations.
- `skills/agentsh-policy-shared/schema-reference.md`: add the field and the supported operation limitation.
- `skills/agentsh-policy-create/SKILL.md` and `skills/agentsh-policy-edit/SKILL.md`: mention the guard when authoring DB mutation policies.

## 7. Compatibility And Risks

Existing policies remain unchanged because the new field defaults to false.

The main operator risk is overestimating the protection. `require_where` prevents accidental omission of a `WHERE` clause; it does not prove that the predicate is selective, tenant-safe, indexed, parameterized, or non-tautological. Documentation and skill guidance should call this out directly.

The main implementation risk is placing `HasWhere` at the wrong level. It belongs on the mutation effect generated from the statement that owns the `WHERE` clause, not on the whole classified statement, because multi-effect statements already fold decisions per effect.
