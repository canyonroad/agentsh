package builtins

import "testing"

func TestDefaultSafeFunctionAllowlist_ContainsCommonBuiltins(t *testing.T) {
	allow := DefaultSafeFunctionAllowlist()
	want := []string{
		"now", "nextval", "currval", "lastval",
		"to_tsvector", "to_tsquery", "plainto_tsquery",
		"count", "sum", "avg", "min", "max",
		"coalesce", "nullif", "greatest", "least",
		"abs", "length", "char_length", "octet_length",
		"lower", "upper", "trim", "btrim", "ltrim", "rtrim",
		"substring", "substr", "left", "right", "position",
		"replace", "split_part", "string_agg", "array_agg",
		"pg_typeof", "version", "current_timestamp",
		"current_date", "current_time", "localtimestamp", "localtime",
		"current_user", "session_user", "user",
	}
	for _, name := range want {
		if _, ok := allow[name]; !ok {
			t.Errorf("default allowlist missing %q", name)
		}
	}
}

func TestDefaultSafeFunctionAllowlist_LowercaseKeys(t *testing.T) {
	allow := DefaultSafeFunctionAllowlist()
	for k := range allow {
		for _, r := range k {
			if r >= 'A' && r <= 'Z' {
				t.Errorf("allowlist key %q has uppercase rune", k)
			}
		}
	}
}
