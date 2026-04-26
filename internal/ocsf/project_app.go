package ocsf

import (
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

// appProjector handles class_uid 6005. Both standard MCP/proxy/secret
// events and agent-internal infra events route here. agentInternal is
// reflected on the proto message so server-side filters can split SOC
// from fleet-health views without depending on the activity_id range.
func appProjector(activity uint32, agentInternal bool) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.ApplicationActivity{
			ClassUid:      u32p(ClassApplicationActivity),
			ActivityId:    u32p(activity),
			CategoryUid:   u32p(6),
			TypeUid:       u32p(ClassApplicationActivity*100 + activity),
			Time:          u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:      strp(severityFromPolicy(ev.Policy)),
			Metadata:      buildMetadata(ev),
			Actor:         buildActor(ev),
			AppName:       strp("agentsh"),
			AgentInternal: boolp(agentInternal),
		}
		if ev.CommandID != "" {
			msg.ResourceUid = strp(ev.CommandID)
		}
		if len(allowed) > 0 {
			// enrichments map: pre-stringified per allowlist transforms.
			// Iterate keys in sorted order so deterministic-marshal output
			// is stable. (proto3 deterministic marshal already sorts map
			// keys by string ordering, but we build the map deterministically
			// for clarity.)
			keys := make([]string, 0, len(allowed))
			for k := range allowed {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			enrichments := make(map[string]string, len(keys))
			for _, k := range keys {
				if s, ok := allowed[k].(string); ok && s != "" {
					enrichments[k] = s
				}
			}
			if len(enrichments) > 0 {
				msg.Enrichments = enrichments
			}
		}
		return msg, nil
	}
}

func init() {
	// Standard / SOC-relevant Application Activity events.
	standardAllow := []FieldRule{
		{Key: "tool_name", Transform: AsString, DestPath: "enrichments.tool_name"},
		{Key: "server_name", Transform: AsString, DestPath: "enrichments.server_name"},
		{Key: "tool_uri", Transform: AsString, DestPath: "enrichments.tool_uri"},
		{Key: "secret_name", Transform: AsString, DestPath: "enrichments.secret_name"},
		{Key: "provider", Transform: AsString, DestPath: "enrichments.provider"},
	}
	standardMappings := map[string]uint32{
		"mcp_tool_called":           AppActivityMCPToolCalled,
		"mcp_tool_seen":             AppActivityMCPToolSeen,
		"mcp_tool_changed":          AppActivityMCPToolChanged,
		"mcp_tools_list_changed":    AppActivityMCPToolsListChanged,
		"mcp_sampling_request":      AppActivityMCPSamplingRequest,
		"mcp_tool_result_inspected": AppActivityMCPToolResultInspected,
		"llm_proxy_started":         AppActivityLLMProxyStarted,
		"llm_proxy_failed":          AppActivityLLMProxyFailed,
		"net_proxy_started":         AppActivityNetProxyStarted,
		"net_proxy_failed":          AppActivityNetProxyFailed,
		"secret_access":             AppActivitySecretAccess,
	}
	for t, activity := range standardMappings {
		register(t, Mapping{
			ClassUID:        ClassApplicationActivity,
			ActivityID:      activity,
			AgentInternal:   false,
			FieldsAllowlist: standardAllow,
			Project:         appProjector(activity, false),
		})
	}

	// Infra / fleet-health events (agent_internal=true).
	infraMappings := map[string]uint32{
		"cgroup_applied":              AppActivityCgroupApplied,
		"cgroup_apply_failed":         AppActivityCgroupApplyFailed,
		"cgroup_cleanup_failed":       AppActivityCgroupCleanupFailed,
		"fuse_mounted":                AppActivityFUSEMounted,
		"fuse_mount_failed":           AppActivityFUSEMountFailed,
		"ebpf_attached":               AppActivityEBPFAttached,
		"ebpf_attach_failed":          AppActivityEBPFAttachFailed,
		"ebpf_collector_failed":       AppActivityEBPFCollectorFailed,
		"ebpf_enforce_disabled":       AppActivityEBPFEnforceDisabled,
		"ebpf_enforce_non_strict":     AppActivityEBPFEnforceNonStrict,
		"ebpf_enforce_refresh_failed": AppActivityEBPFEnforceRefreshFailed,
		"ebpf_unavailable":            AppActivityEBPFUnavailable,
		"wrap_init":                   AppActivityWrapInit,
		"fsevents_error":              AppActivityFSEventsError,
		"integrity_chain_rotated":     AppActivityIntegrityChainRotated,
		"policy_created":              AppActivityPolicyCreated,
		"policy_updated":              AppActivityPolicyUpdated,
		"policy_deleted":              AppActivityPolicyDeleted,
		"session_created":             AppActivitySessionCreated,
		"session_destroyed":           AppActivitySessionDestroyed,
		"session_expired":             AppActivitySessionExpired,
		"session_updated":             AppActivitySessionUpdated,
	}
	infraAllow := []FieldRule{
		{Key: "reason", Transform: AsString, DestPath: "enrichments.reason"},
		{Key: "policy_name", Transform: AsString, DestPath: "enrichments.policy_name"},
		{Key: "rotation_reason", Transform: AsString, DestPath: "enrichments.rotation_reason"},
	}
	for t, activity := range infraMappings {
		register(t, Mapping{
			ClassUID:        ClassApplicationActivity,
			ActivityID:      activity,
			AgentInternal:   true,
			FieldsAllowlist: infraAllow,
			Project:         appProjector(activity, true),
		})
	}
}
