package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func networkProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.NetworkActivity{
			ClassUid:       u32p(ClassNetworkActivity),
			ActivityId:     u32p(activity),
			CategoryUid:    u32p(4),
			TypeUid:        u32p(ClassNetworkActivity*100 + activity),
			Time:           u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:       strp(severityFromPolicy(ev.Policy)),
			Metadata:       buildMetadata(ev),
			Actor:          buildActor(ev),
			DstEndpoint:    buildDstEndpoint(ev),
			ConnectionInfo: buildConnInfo(ev),
		}
		if rt, ok := allowed["redirect_target"].(string); ok && rt != "" {
			msg.RedirectTarget = strp(rt)
		}
		if ev.Policy != nil {
			if d := string(ev.Policy.Decision); d != "" {
				msg.PolicyDecision = strp(d)
			}
			if ev.Policy.Rule != "" {
				msg.PolicyRule = strp(ev.Policy.Rule)
			}
		}
		return msg, nil
	}
}

func buildDstEndpoint(ev types.Event) *ocsfpb.Endpoint {
	if ev.Domain == "" && ev.Remote == "" {
		return nil
	}
	e := &ocsfpb.Endpoint{}
	if ev.Domain != "" {
		e.Domain = strp(ev.Domain)
		e.Hostname = strp(ev.Domain)
	}
	if ev.Remote != "" {
		e.Ip = strp(ev.Remote)
	}
	return e
}

func buildConnInfo(ev types.Event) *ocsfpb.ConnectionInfo {
	ci := &ocsfpb.ConnectionInfo{}
	populated := false
	switch ev.Type {
	case "unix_socket_op":
		ci.ProtocolName = strp("unix")
		populated = true
		if ev.Abstract {
			ci.IsUnixAbstract = boolp(true)
		}
	case "net_connect", "connection_allowed", "connect_redirect", "ptrace_network", "mcp_network_connection":
		ci.ProtocolName = strp("tcp")
		ci.Direction = strp("Outbound")
		populated = true
	}
	if !populated {
		return nil
	}
	return ci
}

func init() {
	netMappings := map[string]uint32{
		"net_connect":            NetworkActivityOpen,
		"connection_allowed":     NetworkActivityOpen,
		"connect_redirect":       NetworkActivityOpen,
		"ptrace_network":         NetworkActivityOpen,
		"unix_socket_op":         NetworkActivityOpen,
		"transparent_net_failed": NetworkActivityClose,
		"transparent_net_ready":  NetworkActivityOpen,
		"transparent_net_setup":  NetworkActivityOpen,
		"mcp_network_connection": NetworkActivityOpen,
	}
	allow := []FieldRule{{
		Key: "redirect_target", Required: false, Transform: AsString, DestPath: "redirect_target",
	}}
	for t, activity := range netMappings {
		register(t, Mapping{
			ClassUID:        ClassNetworkActivity,
			ActivityID:      activity,
			FieldsAllowlist: allow,
			Project:         networkProjector(activity),
		})
	}
}
