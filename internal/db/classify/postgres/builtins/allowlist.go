package builtins

// DefaultSafeFunctionAllowlist returns the curated set of immutable PostgreSQL
// builtin function names safe to treat as `read` when
// policies.db.escalate_unknown_functions is enabled.
//
// All keys are lowercase canonical names. Schema-qualified variants are not
// included; the canonicalFuncName walker matches bare names against the
// shorter form. Operators with custom search_path setups that prefer
// "pg_catalog.*" should add those keys explicitly via
// policies.db.safe_function_allowlist.
//
// This list is best-effort and conservative. It excludes anything stable but
// not provably immutable (e.g., functions that depend on timezone settings)
// and anything user-replaceable via search_path shadowing. When in doubt,
// operators should extend the allowlist via config rather than expect this
// list to be exhaustive.
func DefaultSafeFunctionAllowlist() map[string]struct{} {
	names := []string{
		// time / sequence
		"now", "current_timestamp", "current_date", "current_time",
		"localtimestamp", "localtime", "statement_timestamp", "transaction_timestamp",
		"clock_timestamp", "timeofday",
		"nextval", "currval", "lastval",
		"extract", "date_part", "date_trunc", "age",
		"to_date", "to_timestamp", "to_char", "to_number",
		// text search
		"to_tsvector", "to_tsquery", "plainto_tsquery", "phraseto_tsquery",
		"websearch_to_tsquery", "ts_rank", "ts_rank_cd", "ts_headline",
		// aggregates (read-only)
		"count", "sum", "avg", "min", "max", "stddev", "variance",
		"string_agg", "array_agg", "json_agg", "jsonb_agg",
		"bit_and", "bit_or", "bool_and", "bool_or", "every",
		// numeric / general
		"abs", "ceil", "ceiling", "floor", "round", "trunc", "sign",
		"power", "sqrt", "exp", "ln", "log", "mod", "div",
		"sin", "cos", "tan", "asin", "acos", "atan", "atan2",
		"degrees", "radians", "pi", "random",
		// string
		"length", "char_length", "character_length", "octet_length", "bit_length",
		"lower", "upper", "initcap",
		"trim", "btrim", "ltrim", "rtrim",
		"substring", "substr", "left", "right", "position", "strpos",
		"replace", "translate", "overlay",
		"split_part", "regexp_replace", "regexp_split_to_array", "regexp_split_to_table",
		"regexp_matches", "concat", "concat_ws", "format",
		"chr", "ascii", "to_hex", "md5",
		// general
		"coalesce", "nullif", "greatest", "least",
		"pg_typeof", "version", "current_schema", "current_schemas",
		"current_database", "current_user", "session_user", "user",
		"current_setting", "inet_client_addr", "inet_server_addr",
		// json / jsonb (selectors only — constructors are stable but cheap)
		"json_extract_path", "json_extract_path_text",
		"jsonb_extract_path", "jsonb_extract_path_text",
		"jsonb_typeof", "json_typeof",
		"json_array_elements", "jsonb_array_elements",
		"json_object_keys", "jsonb_object_keys",
		// array
		"array_length", "array_lower", "array_upper", "cardinality",
		"unnest", "array_to_string", "string_to_array", "array_position",
	}
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}
