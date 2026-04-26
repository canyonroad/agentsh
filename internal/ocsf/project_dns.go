package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func dnsProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.DNSActivity{
			ClassUid:    u32p(ClassDNSActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(4),
			TypeUid:     u32p(ClassDNSActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
		}
		q := &ocsfpb.DNSQuery{Class: strp("IN")}
		if ev.Domain != "" {
			q.Hostname = strp(ev.Domain)
		} else if v, ok := allowed["hostname"].(string); ok && v != "" {
			q.Hostname = strp(v)
		}
		if v, ok := allowed["rrtype_name"].(string); ok && v != "" {
			q.TypeName = strp(v)
		}
		if v, ok := allowed["rrtype"].(uint32); ok && v != 0 {
			q.Type = u32p(v)
		}
		msg.Query = q
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

func init() {
	allow := []FieldRule{
		{Key: "hostname", Transform: AsString, DestPath: "query.hostname"},
		{Key: "rrtype", Transform: AsUint32, DestPath: "query.type"},
		{Key: "rrtype_name", Transform: AsString, DestPath: "query.type_name"},
		{Key: "redirect_target", Transform: AsString, DestPath: "redirect_target"},
	}
	register("dns_query", Mapping{
		ClassUID: ClassDNSActivity, ActivityID: DNSActivityQuery,
		FieldsAllowlist: allow, Project: dnsProjector(DNSActivityQuery),
	})
	register("dns_redirect", Mapping{
		ClassUID: ClassDNSActivity, ActivityID: DNSActivityQuery,
		FieldsAllowlist: allow, Project: dnsProjector(DNSActivityQuery),
	})
}
