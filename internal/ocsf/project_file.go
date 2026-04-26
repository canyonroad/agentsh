package ocsf

import (
	"path/filepath"

	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

func fileProjector(activity uint32) Projector {
	return func(ev types.Event, allowed map[string]any) (proto.Message, error) {
		msg := &ocsfpb.FileSystemActivity{
			ClassUid:    u32p(ClassFileSystemActivity),
			ActivityId:  u32p(activity),
			CategoryUid: u32p(1),
			TypeUid:     u32p(ClassFileSystemActivity*100 + activity),
			Time:        u64p(uint64(ev.Timestamp.UTC().UnixNano())),
			Severity:    strp(severityFromPolicy(ev.Policy)),
			Metadata:    buildMetadata(ev),
			Actor:       buildActor(ev),
			File:        buildFile(ev),
			Operation:   strpOrNil(ev.Operation),
		}
		if ev.Type == "file_rename" || ev.Type == "file_renamed" {
			if old, ok := allowed["from_path"].(string); ok && old != "" {
				msg.FileDiff = &ocsfpb.File{
					Path: strp(old),
					Name: strp(filepath.Base(old)),
				}
			}
		}
		if ev.Type == "file_soft_deleted" {
			msg.SoftDeleted = boolp(true)
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

func buildActor(ev types.Event) *ocsfpb.Actor {
	if ev.PID == 0 && ev.SessionID == "" {
		return nil
	}
	a := &ocsfpb.Actor{Process: &ocsfpb.Process{}}
	if ev.PID > 0 {
		a.Process.Pid = u64p(uint64(ev.PID))
	}
	if ev.SessionID != "" {
		a.Process.SessionUid = strp(ev.SessionID)
	}
	if ev.CommandID != "" {
		a.Process.CommandUid = strp(ev.CommandID)
	}
	return a
}

func buildFile(ev types.Event) *ocsfpb.File {
	if ev.Path == "" && ev.Filename == "" {
		return nil
	}
	path := ev.Path
	if path == "" {
		path = ev.Filename
	}
	return &ocsfpb.File{
		Path:       strp(path),
		Name:       strp(filepath.Base(path)),
		RawPath:    strpOrNil(ev.RawFilename),
		IsAbstract: boolPtrIfTrue(ev.Abstract),
	}
}

func boolPtrIfTrue(b bool) *bool {
	if !b {
		return nil
	}
	return boolp(true)
}

func init() {
	fileMappings := map[string]uint32{
		"file_open":         FileActivityRead,
		"file_read":         FileActivityRead,
		"file_write":        FileActivityUpdate,
		"file_create":       FileActivityCreate,
		"file_created":      FileActivityCreate,
		"file_delete":       FileActivityDelete,
		"file_deleted":      FileActivityDelete,
		"file_chmod":        FileActivitySetAttributes,
		"file_mkdir":        FileActivityCreate,
		"file_rmdir":        FileActivityDelete,
		"file_rename":       FileActivityRename,
		"file_renamed":      FileActivityRename,
		"file_modified":     FileActivityUpdate,
		"file_soft_deleted": FileActivityDelete,
		"file_unknown":      FileActivityUnknown,
		"ptrace_file":       FileActivityRead,
		"registry_write":    FileActivityUpdate,
		"registry_error":    FileActivityUpdate,
	}
	renameAllowlist := []FieldRule{{
		Key: "from_path", Required: false, Transform: AsString, DestPath: "file_diff.path",
	}}
	for t, activity := range fileMappings {
		var allow []FieldRule
		if t == "file_rename" || t == "file_renamed" {
			allow = renameAllowlist
		}
		register(t, Mapping{
			ClassUID:        ClassFileSystemActivity,
			ActivityID:      activity,
			FieldsAllowlist: allow,
			Project:         fileProjector(activity),
		})
	}
}
