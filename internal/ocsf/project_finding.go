package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func findingProjector(activity uint32, findingType string) Projector {
	return func(ev types.Event, _ map[string]any) (proto.Message, error) {
		msg := &ocsfpb.DetectionFinding{
			ClassUid:    u32p(ClassDetectionFinding),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(2),
			TypeUid:     u32p(ClassDetectionFinding*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp("Medium"),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
			FindingInfo: &ocsfpb.FindingInfo{
				Title:      strp(ev.Type),
				FindingUid: strpOrNil(ev.ID),
				Types:      strp(findingType),
			},
		}
		if ev.Policy != nil {
			if ev.Policy.Message != "" {
				msg.FindingInfo.Desc = strp(ev.Policy.Message)
			}
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
			if ev.Policy.ThreatFeed != "" {
				msg.ThreatFeed = strp(ev.Policy.ThreatFeed)
			}
			if ev.Policy.ThreatMatch != "" {
				msg.ThreatMatch = strp(ev.Policy.ThreatMatch)
			}
			if ev.Policy.ThreatAction != "" {
				msg.ThreatAction = strp(ev.Policy.ThreatAction)
			}
		}
		return msg, nil
	}
}

func init() {
	findingTypes := map[string]string{
		"command_policy":                   "policy_decision",
		"seccomp_blocked":                  "policy_decision",
		"seccomp_socket_family_blocked":    "policy_decision",
		"agent_detected":                   "agent_self_detected",
		"taint_created":                    "taint",
		"taint_propagated":                 "taint",
		"taint_removed":                    "taint",
		"mcp_cross_server_blocked":         "policy_decision",
		"mcp_tool_call_intercepted":        "policy_decision",
	}
	for t, ft := range findingTypes {
		register(t, Mapping{
			ClassUID:        ClassDetectionFinding,
			ActivityID:      FindingActivityCreate,
			FieldsAllowlist: nil,
			Project:         findingProjector(FindingActivityCreate, ft),
		})
	}
}
