package ocsf

// skiplist enumerates ev.Type literal values that appear in the source
// tree but are NOT production telemetry — test fixtures, placeholders,
// throwaway values used only in unit tests. The exhaustiveness CI walks
// every ev.Type literal and asserts it is either registered, in
// pendingTypes, or in this skiplist.
//
// Each entry's value is the reason it is skiplisted. The reason MUST
// be non-empty (asserted by skiplist_test.go) and SHOULD reference the
// kind of test that emits it.
//
// CRITICAL: a value listed here MUST NOT be a real production Type.
// TestSkiplistDoesNotShadowRegistry guards against that by asserting
// skiplist ∩ (registry ∪ pendingTypes) = ∅ on package init. Adding a
// production-flavored value here is a CI failure, not a silent drop.
var skiplist = map[string]string{
	"a":                "test fixture: short alphabet sentinel in event_query/composite tests",
	"b":                "test fixture: short alphabet sentinel",
	"x":                "test fixture: short alphabet sentinel",
	"y":                "test fixture: short alphabet sentinel",
	"test":             "test fixture: generic placeholder",
	"test_event":       "test fixture: generic placeholder",
	"demo":             "test fixture: example/demo path",
	"hello":            "test fixture: greeting placeholder",
	"phone":            "test fixture: contact placeholder",
	"license":          "test fixture: placeholder used in license-related tests",
	"ok":               "test fixture: success-flag placeholder",
	"none":             "test fixture: zero-value placeholder",
	"live":             "test fixture: liveness probe placeholder",
	"email":            "test fixture: contact placeholder",
	"external":         "test fixture: source classifier placeholder",
	"self":             "test fixture: self-reference placeholder",
	"invalid":          "test fixture: explicit invalid sentinel",
	"invalid_type":     "test fixture: explicit invalid sentinel",
	"pid_range":        "test fixture: pid_range query selector test",
	"signal":           "test fixture: signal placeholder",
	"resize":           "test fixture: pty resize placeholder",
	"rotate":           "test fixture: rotation placeholder",
	"after_rotate":     "test fixture: post-rotation placeholder",
	"start":            "test fixture: lifecycle placeholder",
	"big_event":        "test fixture: oversize-event boundary test",
	"command":          "test fixture: command placeholder",
	"fatal_sidecar":    "test fixture: fatal-sidecar drill placeholder",
	"file":             "test fixture: file placeholder distinct from file_open et al",
	"malware":          "test fixture: detection placeholder",
	"network":          "test fixture: network placeholder distinct from net_connect et al",
	"process":          "test fixture: process placeholder distinct from process_start",
	"session":          "test fixture: session placeholder distinct from session_created et al",
	"sse":              "test fixture: server-sent events placeholder",
	"stream":           "test fixture: stream placeholder",
	"unix":             "test fixture: unix-domain placeholder",
	"vulnerability":    "test fixture: vulnerability placeholder",
	"event":            "test fixture: generic event placeholder",
	"agent_detected_t": "test fixture: agent_detected variant in tests",
	"stdio":            "test fixture: stdio source classifier",
	"children":         "test fixture: children placeholder",
}
