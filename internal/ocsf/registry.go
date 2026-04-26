package ocsf

// registry maps every production agentsh ev.Type to its OCSF Mapping.
// Per-class projector files (project_*.go) populate it via package
// init() functions; this file holds only the central declaration and
// the rollout tracker.
//
// Determinism note: registry values are read-only after package init.
// Map() reads but never mutates the registry.
var registry = map[string]Mapping{}

// pendingTypes lists production agentsh ev.Type values that the
// mapper does NOT yet handle. Populated in this file initially; each
// per-class projector PR removes its types as it lands.
//
// The exhaustiveness CI test in exhaustiveness_test.go uses this set:
// for any ev.Type discovered in the source tree, the test asserts
//
//	_, registered := registry[t]
//	_, skipped    := skiplist[t]
//	_, pending    := pendingTypes[t]
//	require registered || skipped || pending
//
// When pendingTypes is empty AND every emitted Type is registered or
// skiplisted, Phase 1 is functionally complete.
var pendingTypes = map[string]struct{}{
	// Process Activity (1007) — Task 16
	"execve":             {},
	"exec":               {},
	"exec_intercept":     {},
	"exec.start":         {},
	"ptrace_execve":      {},
	"command_started":    {},
	"command_executed":   {},
	"command_finished":   {},
	"command_killed":     {},
	"command_redirected": {},
	"command_redirect":   {},
	"process_start":      {},
	"exit":               {},
	// File System Activity (1001) — Task 17
	"file_open":         {},
	"file_read":         {},
	"file_write":        {},
	"file_create":       {},
	"file_created":      {},
	"file_delete":       {},
	"file_deleted":      {},
	"file_chmod":        {},
	"file_mkdir":        {},
	"file_rmdir":        {},
	"file_rename":       {},
	"file_renamed":      {},
	"file_modified":     {},
	"file_soft_deleted": {},
	"ptrace_file":       {},
	"registry_write":    {},
	"registry_error":    {},
	// Network Activity (4001) — Task 18
	"net_connect":            {},
	"connection_allowed":     {},
	"connect_redirect":       {},
	"ptrace_network":         {},
	"unix_socket_op":         {},
	"transparent_net_failed": {},
	"transparent_net_ready":  {},
	"transparent_net_setup":  {},
	"mcp_network_connection": {},
	// HTTP Activity (4002) — Task 19
	"http":                       {},
	"net_http_request":           {},
	"http_service_denied_direct": {},
	// DNS Activity (4003) — Task 20
	"dns_query":    {},
	"dns_redirect": {},
	// Detection Finding (2004) — Task 21
	"command_policy":            {},
	"seccomp_blocked":           {},
	"agent_detected":            {},
	"taint_created":             {},
	"taint_propagated":          {},
	"taint_removed":             {},
	"mcp_cross_server_blocked":  {},
	"mcp_tool_call_intercepted": {},
	// Application Activity (6005) — Task 22
	"mcp_tool_called":             {},
	"mcp_tool_seen":               {},
	"mcp_tool_changed":            {},
	"mcp_tools_list_changed":      {},
	"mcp_sampling_request":        {},
	"mcp_tool_result_inspected":   {},
	"llm_proxy_started":           {},
	"llm_proxy_failed":            {},
	"net_proxy_started":           {},
	"net_proxy_failed":            {},
	"secret_access":               {},
	"cgroup_applied":              {},
	"cgroup_apply_failed":         {},
	"cgroup_cleanup_failed":       {},
	"fuse_mounted":                {},
	"fuse_mount_failed":           {},
	"ebpf_attached":               {},
	"ebpf_attach_failed":          {},
	"ebpf_collector_failed":       {},
	"ebpf_enforce_disabled":       {},
	"ebpf_enforce_non_strict":     {},
	"ebpf_enforce_refresh_failed": {},
	"ebpf_unavailable":            {},
	"wrap_init":                   {},
	"fsevents_error":              {},
	"integrity_chain_rotated":     {},
	"policy_created":              {},
	"policy_updated":              {},
	"policy_deleted":              {},
	"session_created":             {},
	"session_destroyed":           {},
	"session_expired":             {},
	"session_updated":             {},
}

// register installs a Mapping in the registry and removes the type
// from pendingTypes. Called from per-class init() in project_*.go.
// Panics if t is already registered or already in skiplist — these
// are package-init bugs that must surface immediately.
func register(t string, m Mapping) {
	if _, ok := registry[t]; ok {
		panic("ocsf: duplicate Mapping for type: " + t)
	}
	if _, ok := skiplist[t]; ok {
		panic("ocsf: cannot register skiplisted type: " + t)
	}
	registry[t] = m
	delete(pendingTypes, t)
}

// skiplist is populated in skiplist.go (Task 12). Declared here as an
// empty map so this skeleton commit compiles standalone.
//
// Task 12 will replace this declaration with one in skiplist.go that
// populates the map literal. The empty placeholder here will then be
// a duplicate-symbol compile error and must be removed in Task 12.
var skiplist = map[string]string{}
