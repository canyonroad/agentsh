package ocsf

import (
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
			// OCSF rename semantics: file = destination, file_diff = source.
			// ev.Path holds the source (from) path as emitted by fuse.go.
			// Fields["to_path"] (or "path2" on darwin ESF) holds the destination.
			dest := ""
			if v, ok := allowed["to_path"].(string); ok && v != "" {
				dest = v
			} else if v, ok := allowed["path2"].(string); ok && v != "" {
				dest = v
			}
			if dest != "" {
				// Destination goes into file (overrides the default ev.Path-based File).
				msg.File = &ocsfpb.File{
					Path: strp(dest),
					Name: strp(basename(dest)),
				}
				// Source goes into file_diff.
				if ev.Path != "" {
					msg.FileDiff = &ocsfpb.File{
						Path: strp(ev.Path),
						Name: strp(basename(ev.Path)),
					}
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
		Name:       strp(basename(path)),
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
		// Dynamically-emitted types (helper-based; not caught by AST walker).
		// See exhaustiveness_test.go comment for context.
		"dir_list":      FileActivityRead,
		"dir_create":    FileActivityCreate,
		"dir_delete":    FileActivityDelete,
		"file_stat":     FileActivityRead,
		"symlink_create": FileActivityCreate,
		"symlink_read":  FileActivityRead,
	}
	// renameAllowlist carries the destination path and the optional
	// cross_mount flag from fuse rename events. to_path is the move
	// destination; ev.Path is the source (from, used for file_diff).
	// Darwin ESF emitters use path2 for the same destination field.
	renameAllowlist := []FieldRule{
		{Key: "to_path", Required: false, Transform: AsString, DestPath: "file.path"},
		{Key: "path2", Required: false, Transform: AsString, DestPath: "file.path"},
	}
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
