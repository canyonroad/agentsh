package ocsf

import (
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

// processProjector builds a *ocsfpb.ProcessActivity from an event
// classified as Process Activity (class_uid 1007).
//
// activity_id is read from the registry Mapping (it differs per Type:
// execve→Launch, exit→Terminate, exec_intercept→Open, ...). The
// projector embeds a Process object (the child) and an Actor with the
// parent (when ev.ParentPID > 0).
func processProjector(activity uint32) Projector {
	return func(ev types.Event, _ map[string]any) (proto.Message, error) {
		msg := &ocsfpb.ProcessActivity{
			ClassUid:    u32p(ClassProcessActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(1),
			TypeUid:     u32p(ClassProcessActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Process:     buildProcess(ev),
		}
		if ev.ParentPID > 0 {
			msg.Actor = &ocsfpb.Actor{
				Process: &ocsfpb.Process{
					Pid: u64p(uint64(ev.ParentPID)),
				},
			}
		}
		if ev.UnwrappedFrom != "" {
			msg.UnwrappedFrom = strp(ev.UnwrappedFrom)
		}
		if ev.PayloadCommand != "" {
			msg.PayloadCommand = strp(ev.PayloadCommand)
		}
		if ev.Truncated {
			msg.Truncated = boolp(true)
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

func buildProcess(ev types.Event) *ocsfpb.Process {
	p := &ocsfpb.Process{}
	if ev.PID > 0 {
		p.Pid = u64p(uint64(ev.PID))
	}
	if ev.ParentPID > 0 {
		p.ParentPid = u64p(uint64(ev.ParentPID))
	}
	if ev.Filename != "" {
		p.Name = strp(filepath.Base(ev.Filename))
		p.File = &ocsfpb.File{
			Path:    strp(ev.Filename),
			Name:    strp(filepath.Base(ev.Filename)),
			RawPath: strpOrNil(ev.RawFilename),
		}
	}
	if len(ev.Argv) > 0 {
		p.CmdLine = strp(strings.Join(ev.Argv, " "))
	}
	if ev.Depth > 0 {
		p.Depth = u32p(uint32(ev.Depth))
	}
	if ev.SessionID != "" {
		p.SessionUid = strp(ev.SessionID)
	}
	if ev.CommandID != "" {
		p.CommandUid = strp(ev.CommandID)
	}
	return p
}

func buildMetadata(ev types.Event) *ocsfpb.Metadata {
	md := &ocsfpb.Metadata{
		Version: strp(SchemaVersion),
		Product: &ocsfpb.Product{
			Name:       strp("agentsh"),
			VendorName: strp("agentsh"),
		},
		LoggedTime: u64p(uint64(ev.Timestamp.UTC().UnixNano())),
		EventCode:  strp(ev.Type),
	}
	if ev.ID != "" {
		md.Uid = strp(ev.ID)
	}
	return md
}

func severityFromPolicy(p *types.PolicyInfo) string {
	if p == nil {
		return "Informational"
	}
	switch string(p.EffectiveDecision) {
	case "deny", "block":
		return "Medium"
	case "warn":
		return "Low"
	default:
		return "Informational"
	}
}

// Pointer helpers for proto3 explicit-presence fields.
func u32p(v uint32) *uint32 { return &v }
func u64p(v uint64) *uint64 { return &v }
func strp(v string) *string { return &v }
func boolp(v bool) *bool    { return &v }

func strpOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func init() {
	// Process Activity Type → activity_id mapping.
	processMappings := map[string]uint32{
		"execve":             ProcessActivityLaunch,
		"exec":               ProcessActivityLaunch,
		"exec.start":         ProcessActivityLaunch,
		"ptrace_execve":      ProcessActivityLaunch,
		"command_started":    ProcessActivityLaunch,
		"command_executed":   ProcessActivityLaunch,
		"process_start":      ProcessActivityLaunch,
		"command_finished":   ProcessActivityTerminate,
		"command_killed":     ProcessActivityTerminate,
		"exit":               ProcessActivityTerminate,
		"exec_intercept":     ProcessActivityOpen,
		"command_redirected": ProcessActivityOpen,
		"command_redirect":   ProcessActivityOpen,
	}
	for t, activity := range processMappings {
		register(t, Mapping{
			ClassUID:        ClassProcessActivity,
			ActivityID:      activity,
			FieldsAllowlist: nil, // process events use only top-level Event columns
			Project:         processProjector(activity),
		})
	}
}
