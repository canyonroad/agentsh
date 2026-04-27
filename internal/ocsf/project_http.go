package ocsf

import (
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func httpProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.HTTPActivity{
			ClassUid:    u32p(ClassHTTPActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(4),
			TypeUid:     u32p(ClassHTTPActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
		}
		req := &ocsfpb.HTTPRequest{}
		anyReq := false
		if v, ok := allowed["method"].(string); ok && v != "" {
			req.HttpMethod = strp(v)
			anyReq = true
		}
		if v, ok := allowed["url"].(string); ok && v != "" {
			req.Url = strp(v)
			anyReq = true
		} else if v, ok := allowed["path"].(string); ok && v != "" {
			// net_http_request emitter stores the URL path as "path" (not "url").
			req.Url = strp(v)
			anyReq = true
		}
		if v, ok := allowed["user_agent"].(string); ok && v != "" {
			req.UserAgent = strp(v)
			anyReq = true
		}
		if v, ok := allowed["http_version"].(string); ok && v != "" {
			req.Version = strp(v)
			anyReq = true
		}
		if v, ok := allowed["host"].(string); ok && v != "" {
			req.Host = strp(v)
			anyReq = true
		}
		if anyReq {
			msg.HttpRequest = req
		}
		resp := &ocsfpb.HTTPResponse{}
		anyResp := false
		if v, ok := allowed["status_code"].(uint32); ok && v != 0 {
			resp.StatusCode = u32p(v)
			anyResp = true
		}
		if v, ok := allowed["response_bytes"].(uint64); ok && v != 0 {
			resp.Length = u64p(v)
			anyResp = true
		}
		if anyResp {
			msg.HttpResponse = resp
		}
		if ev.Domain != "" || ev.Remote != "" {
			msg.DstEndpoint = buildDstEndpoint(ev)
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
	httpAllow := []FieldRule{
		{Key: "method", Transform: AsString, DestPath: "http_request.http_method"},
		{Key: "url", Transform: AsString, DestPath: "http_request.url"},
		// net_http_request emitter stores the URL as "path" (proxy plain-HTTP path),
		// not "url". Allowlist both; projector above prefers "url" then falls back to "path".
		{Key: "path", Transform: AsString, DestPath: "http_request.url"},
		{Key: "host", Transform: AsString, DestPath: "http_request.host"},
		{Key: "user_agent", Transform: AsString, DestPath: "http_request.user_agent"},
		{Key: "http_version", Transform: AsString, DestPath: "http_request.version"},
		{Key: "status_code", Transform: AsUint32, DestPath: "http_response.status_code"},
		{Key: "response_bytes", Transform: AsUint64, DestPath: "http_response.length"},
	}
	httpMappings := map[string]uint32{
		"http":                       HTTPActivityRequest,
		"net_http_request":           HTTPActivityRequest,
		"http_service_denied_direct": HTTPActivityRequest,
	}
	for t, activity := range httpMappings {
		register(t, Mapping{
			ClassUID:        ClassHTTPActivity,
			ActivityID:      activity,
			FieldsAllowlist: httpAllow,
			Project:         httpProjector(activity),
		})
	}
}
