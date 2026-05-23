package ocsf

import (
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1/ocsf"
)

// processProjector builds a *ocsfpb.ProcessActivity from an event
// classified as Process Activity (class_uid 1007).
//
// activity_id is read from the registry Mapping (it differs per Type:
// execve→Launch, exit→Terminate, exec_intercept→Open, ...). The
// projector embeds a Process object (the child) and an Actor with the
// parent (when ev.ParentPID > 0).
func processProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.ProcessActivity{
			ClassUid:    u32p(ClassProcessActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(1),
			TypeUid:     u32p(ClassProcessActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Process:     buildProcess(ev, allowed),
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
		// Lifecycle events (command_started/finished/killed/executed)
		// carry exit_code in ev.Fields. The allowlist transforms it to
		// uint32; absent or negative codes leave ExitCode unset.
		if ec, ok := allowed["exit_code"].(uint32); ok {
			msg.ExitCode = u32p(ec)
		}
		return msg, nil
	}
}

// buildProcess builds the embedded Process. Typed event fields (PID,
// Filename, Argv) are the primary source. For lifecycle events
// (command_started/finished/killed) the kernel/syscall fields are
// empty — the executable and args land in ev.Fields, projected through
// the allowlist into `allowed`. When the typed source is empty we fall
// back to the allowed map so process.file.path and process.cmd_line
// are populated for those event types too.
func buildProcess(ev types.Event, allowed map[string]any) *ocsfpb.Process {
	p := &ocsfpb.Process{}
	if ev.PID > 0 {
		p.Pid = u64p(uint64(ev.PID))
	}
	if ev.ParentPID > 0 {
		p.ParentPid = u64p(uint64(ev.ParentPID))
	}
	filename := ev.Filename
	if filename == "" {
		if v, ok := allowed["command"].(string); ok {
			filename = v
		}
	}
	if filename != "" {
		p.Name = strp(basename(filename))
		p.File = &ocsfpb.File{
			Path:    strp(filename),
			Name:    strp(basename(filename)),
			RawPath: strpOrNil(ev.RawFilename),
		}
	}
	switch {
	case len(ev.Argv) > 0:
		p.CmdLine = strp(strings.Join(ev.Argv, " "))
	case filename != "":
		// argv was not in ev.Argv. Reconstruct cmd_line from the lifecycle
		// command + args fallback. argv[0] convention is the executable;
		// mirror that for OCSF cmd_line.
		parts := []string{filename}
		if args, ok := allowed["args"].([]string); ok {
			parts = append(parts, args...)
		}
		p.CmdLine = strp(strings.Join(parts, " "))
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

// basename returns the last component of p, splitting on BOTH '/' and
// '\\' regardless of OS. This keeps the OCSF payload deterministic
// across Linux/macOS/Windows, which is load-bearing for the chain hash.
//
// Unlike filepath.Base, the result is the same on every platform —
// critical for paths that contain backslashes from Windows registry
// hives (e.g., "HKLM\\Software\\Foo") or Windows file paths
// (e.g., "C:\\Windows\\system32\\foo.exe") regardless of where the
// agent runs.
//
// For inputs with no separator, returns the input unchanged. For an
// empty string, returns "".
func basename(p string) string {
	last := -1
	for i := 0; i < len(p); i++ {
		if p[i] == '/' || p[i] == '\\' {
			last = i
		}
	}
	return p[last+1:]
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
			FieldsAllowlist: processFieldsAllowlistFor(t),
			Project:         processProjector(activity),
		})
	}
}

// lifecycleProcessAllowlist projects ev.Fields keys carried by the
// command_started / command_finished / command_killed / command_executed
// emit sites in internal/api (exec_stream.go and core.go). Kernel-sourced
// process events (execve, exec_intercept, exit, ...) populate the typed
// ev.Filename / ev.Argv / ev.PID fields directly and don't need this.
var lifecycleProcessAllowlist = []FieldRule{
	{Key: "command", Transform: AsString, DestPath: "process.file.path, process.cmd_line"},
	{Key: "args", Transform: AsStringSlice, DestPath: "process.cmd_line"},
	{Key: "exit_code", Transform: AsUint32, DestPath: "exit_code"},
}

func processFieldsAllowlistFor(t string) []FieldRule {
	switch t {
	case "command_started", "command_finished", "command_killed", "command_executed":
		return lifecycleProcessAllowlist
	}
	return nil
}
