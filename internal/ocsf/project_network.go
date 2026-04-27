package ocsf

import (
	"net"
	"strconv"

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
		if rt, ok := allowed["redirect_to"].(string); ok && rt != "" {
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
		// ev.Remote may be "host:port" or a bare IP/hostname.
		// net.SplitHostPort handles IPv6 brackets correctly.
		if host, portStr, err := net.SplitHostPort(ev.Remote); err == nil {
			if p, err := strconv.ParseUint(portStr, 10, 32); err == nil {
				e.Port = u32p(uint32(p))
			}
			// If domain is already set, keep it; only override hostname
			// if the host part is non-empty and domain was not set.
			if host != "" {
				if e.Hostname == nil {
					e.Hostname = strp(host)
				}
				e.Ip = strp(host)
			}
		} else {
			// Bare IP or hostname without port.
			e.Ip = strp(ev.Remote)
		}
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
	// transparent_net_setup, transparent_net_ready, and transparent_net_failed
	// are lifecycle events about the transparent-networking subsystem itself
	// (e.g. tproxy/redirect table setup or teardown), not events for an
	// individual network connection. They carry no protocol, direction, or
	// endpoint information, so ConnectionInfo is intentionally omitted (nil).
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
		// transparent_net_ready and transparent_net_setup are lifecycle events
		// about the transparent-networking subsystem, not individual connections.
		// They are mapped to NetworkActivityOpen for event-class consistency
		// but carry no ConnectionInfo (no protocol/direction — see buildConnInfo).
		"transparent_net_ready":  NetworkActivityOpen,
		"transparent_net_setup":  NetworkActivityOpen,
		"mcp_network_connection": NetworkActivityOpen,
		// Dynamically-emitted; not caught by AST walker — see exhaustiveness_test.go.
		"net_close": NetworkActivityClose,
	}
	// redirect_to is the real field key used by proxy.go and transparent_tcp.go
	// emitters (was incorrectly allowlisted as redirect_target in the original code).
	allow := []FieldRule{{
		Key: "redirect_to", Required: false, Transform: AsString, DestPath: "redirect_target",
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
