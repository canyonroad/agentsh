package ocsf

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/agentsh/agentsh/pkg/types"
	ocsfpb "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf"
)

var updateGoldens = flag.Bool("update", false, "regenerate golden files")

func TestMap_UnmappedTypeReturnsErrUnmappedType(t *testing.T) {
	m := New()
	ev := types.Event{Type: "definitely_not_in_registry_xyz", Timestamp: time.Unix(0, 0)}
	_, err := m.Map(ev)
	if !errors.Is(err, ErrUnmappedType) {
		t.Fatalf("got %v, want errors.Is(ErrUnmappedType)", err)
	}
	var ute *UnmappedTypeError
	if !errors.As(err, &ute) {
		t.Fatalf("got %v, want *UnmappedTypeError", err)
	}
	if ute.Type != "definitely_not_in_registry_xyz" {
		t.Fatalf("UnmappedTypeError.Type = %q", ute.Type)
	}
}

// TestMapDeterministic asserts that for any registered event, mapping
// 1000 times produces byte-identical Payload. Run on a sample of
// events covering every class. New event Types added in per-class
// PRs MUST appear in deterministicSampleEvents() — the helper below
// is the test contract.
func TestMapDeterministic(t *testing.T) {
	m := New()
	for _, ev := range deterministicSampleEvents() {
		ev := ev
		t.Run(ev.Type, func(t *testing.T) {
			first, err := m.Map(ev)
			if err != nil {
				t.Skipf("Map(%q) error %v — Type not yet implemented", ev.Type, err)
			}
			for i := 0; i < 1000; i++ {
				got, err := m.Map(ev)
				if err != nil {
					t.Fatalf("iteration %d: %v", i, err)
				}
				if !bytes.Equal(first.Payload, got.Payload) {
					t.Fatalf("iteration %d: payload diverged: %x vs %x", i, first.Payload, got.Payload)
				}
				if got.OCSFClassUID != first.OCSFClassUID || got.OCSFActivityID != first.OCSFActivityID {
					t.Fatalf("iteration %d: class/activity diverged", i)
				}
			}
		})
	}
}

// deterministicSampleEvents returns one representative Event per
// registered Type. As per-class projectors land, each PR appends its
// fixtures here. The TestMapDeterministic skips Types whose Map call
// returns an error — that lets the test pass during incremental rollout
// and makes it strictly tighten as Types are registered.
func deterministicSampleEvents() []types.Event {
	return goldenSampleEvents()
}

// TestGoldens runs Map for every entry in goldenSampleEvents(),
// projects the resulting proto payload to JSON via protojson, and
// compares against testdata/golden/<type>.json. With -update,
// regenerates the golden files instead of comparing.
//
// Skips Types whose Map returns an error so the test stays green
// during incremental per-class rollout.
func TestGoldens(t *testing.T) {
	m := New()
	for _, ev := range goldenSampleEvents() {
		ev := ev
		t.Run(ev.Type, func(t *testing.T) {
			mapped, err := m.Map(ev)
			if err != nil {
				t.Skipf("Map(%q) error %v — Type not yet implemented", ev.Type, err)
			}
			msg, err := decodePayloadForGolden(mapped.OCSFClassUID, mapped.Payload)
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			gotJSON, err := protojson.MarshalOptions{
				Multiline:       true,
				Indent:          "  ",
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}.Marshal(msg)
			if err != nil {
				t.Fatalf("protojson: %v", err)
			}
			path := filepath.Join("testdata", "golden", ev.Type+".json")
			if *updateGoldens {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, gotJSON, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (run with -update to create)", path, err)
			}
			if !bytes.Equal(normalizeJSON(t, gotJSON), normalizeJSON(t, want)) {
				t.Errorf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", ev.Type, gotJSON, want)
			}
		})
	}
}

// decodePayloadForGolden picks the right proto.Message type for a
// given class_uid so protojson can marshal its fields. Per-class PRs
// extend this switch.
func decodePayloadForGolden(classUID uint32, payload []byte) (proto.Message, error) {
	var msg proto.Message
	switch classUID {
	case ClassProcessActivity:
		msg = &ocsfpb.ProcessActivity{}
	case ClassFileSystemActivity:
		msg = &ocsfpb.FileSystemActivity{}
	case ClassNetworkActivity:
		msg = &ocsfpb.NetworkActivity{}
	case ClassHTTPActivity:
		msg = &ocsfpb.HTTPActivity{}
	case ClassDNSActivity:
		msg = &ocsfpb.DNSActivity{}
	case ClassDetectionFinding:
		msg = &ocsfpb.DetectionFinding{}
	case ClassApplicationActivity:
		msg = &ocsfpb.ApplicationActivity{}
	default:
		return nil, errors.New("decodePayloadForGolden: unknown class_uid")
	}
	if err := proto.Unmarshal(payload, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func normalizeJSON(t *testing.T, in []byte) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(in, &v); err != nil {
		t.Fatalf("json normalize: %v", err)
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// goldenSampleEvents returns the canonical fixture per registered
// Type. Each per-class PR appends its fixtures here.
func goldenSampleEvents() []types.Event {
	t0 := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	return []types.Event{
		// Process Activity (1007) — Task 16
		{
			ID: "ev-execve-1", Type: "execve", Timestamp: t0,
			SessionID: "sess-1", CommandID: "cmd-1",
			PID: 1234, ParentPID: 1, Depth: 2,
			Filename: "/usr/bin/curl", RawFilename: "curl",
			Argv: []string{"curl", "-sS", "https://example.com"},
		},
		{ID: "ev-exec-1", Type: "exec", Timestamp: t0, PID: 100, Filename: "/bin/sh"},
		{ID: "ev-exec-intercept-1", Type: "exec_intercept", Timestamp: t0, PID: 101, Filename: "/bin/dangerous",
			Policy: &types.PolicyInfo{Decision: "deny", EffectiveDecision: "deny", Rule: "no-fork"}},
		{ID: "ev-exec-start-1", Type: "exec.start", Timestamp: t0, PID: 102, Filename: "/bin/ls"},
		{ID: "ev-ptrace-execve-1", Type: "ptrace_execve", Timestamp: t0, PID: 103, Filename: "/bin/ls"},
		{ID: "ev-cmd-started-1", Type: "command_started", Timestamp: t0, PID: 110, CommandID: "c1"},
		{ID: "ev-cmd-executed-1", Type: "command_executed", Timestamp: t0, PID: 111, CommandID: "c1"},
		{ID: "ev-cmd-finished-1", Type: "command_finished", Timestamp: t0, PID: 110, CommandID: "c1"},
		{ID: "ev-cmd-killed-1", Type: "command_killed", Timestamp: t0, PID: 110, CommandID: "c1"},
		{ID: "ev-cmd-redirected-1", Type: "command_redirected", Timestamp: t0, PID: 120, UnwrappedFrom: "sudo", PayloadCommand: "/usr/bin/find"},
		{ID: "ev-cmd-redirect-1", Type: "command_redirect", Timestamp: t0, PID: 121},
		{ID: "ev-process-start-1", Type: "process_start", Timestamp: t0, PID: 130},
		{ID: "ev-exit-1", Type: "exit", Timestamp: t0, PID: 140},

		// File System Activity (1001) — Task 17
		{ID: "ev-file-open-1", Type: "file_open", Timestamp: t0, PID: 200, Path: "/etc/hosts", Operation: "open"},
		{ID: "ev-file-read-1", Type: "file_read", Timestamp: t0, PID: 201, Path: "/etc/passwd", Operation: "read"},
		{ID: "ev-file-write-1", Type: "file_write", Timestamp: t0, PID: 202, Path: "/tmp/out", Operation: "write"},
		{ID: "ev-file-create-1", Type: "file_create", Timestamp: t0, PID: 203, Path: "/tmp/new"},
		{ID: "ev-file-created-1", Type: "file_created", Timestamp: t0, PID: 204, Path: "/tmp/done"},
		{ID: "ev-file-delete-1", Type: "file_delete", Timestamp: t0, PID: 205, Path: "/tmp/old"},
		{ID: "ev-file-deleted-1", Type: "file_deleted", Timestamp: t0, PID: 206, Path: "/tmp/removed"},
		{ID: "ev-file-chmod-1", Type: "file_chmod", Timestamp: t0, PID: 207, Path: "/tmp/perm"},
		{ID: "ev-file-mkdir-1", Type: "file_mkdir", Timestamp: t0, PID: 208, Path: "/tmp/dir"},
		{ID: "ev-file-rmdir-1", Type: "file_rmdir", Timestamp: t0, PID: 209, Path: "/tmp/dir"},
		{ID: "ev-file-rename-1", Type: "file_rename", Timestamp: t0, PID: 210, Path: "/tmp/new", Fields: map[string]any{"from_path": "/tmp/old"}},
		{ID: "ev-file-renamed-1", Type: "file_renamed", Timestamp: t0, PID: 211, Path: "/tmp/dest", Fields: map[string]any{"from_path": "/tmp/src"}},
		{ID: "ev-file-modified-1", Type: "file_modified", Timestamp: t0, PID: 212, Path: "/tmp/changed"},
		{ID: "ev-file-soft-deleted-1", Type: "file_soft_deleted", Timestamp: t0, PID: 213, Path: "/tmp/soft"},
		{ID: "ev-file-unknown-1", Type: "file_unknown", Timestamp: t0, PID: 214, Path: "/tmp/unknown"},
		{ID: "ev-ptrace-file-1", Type: "ptrace_file", Timestamp: t0, PID: 215, Path: "/etc/shadow"},
		{ID: "ev-registry-write-1", Type: "registry_write", Timestamp: t0, PID: 216, Path: "HKLM\\Software\\Foo"},
		{ID: "ev-registry-error-1", Type: "registry_error", Timestamp: t0, PID: 217, Path: "HKLM\\Software\\Bar"},

		// Network Activity (4001) — Task 18
		{ID: "ev-net-connect-1", Type: "net_connect", Timestamp: t0, PID: 300, Domain: "example.com", Remote: "93.184.216.34"},
		{ID: "ev-conn-allowed-1", Type: "connection_allowed", Timestamp: t0, PID: 301, Domain: "ok.example", Remote: "10.0.0.1"},
		{ID: "ev-connect-redirect-1", Type: "connect_redirect", Timestamp: t0, PID: 302, Domain: "in.example", Fields: map[string]any{"redirect_target": "out.example:443"}},
		{ID: "ev-ptrace-network-1", Type: "ptrace_network", Timestamp: t0, PID: 303, Domain: "trace.example"},
		{ID: "ev-unix-sock-1", Type: "unix_socket_op", Timestamp: t0, PID: 304, Path: "/run/agentsh.sock", Abstract: false},
		{ID: "ev-tnet-failed-1", Type: "transparent_net_failed", Timestamp: t0},
		{ID: "ev-tnet-ready-1", Type: "transparent_net_ready", Timestamp: t0},
		{ID: "ev-tnet-setup-1", Type: "transparent_net_setup", Timestamp: t0},
		{ID: "ev-mcp-net-1", Type: "mcp_network_connection", Timestamp: t0, PID: 305, Domain: "mcp.example", Remote: "10.0.0.5"},

		// HTTP Activity (4002) — Task 19
		{ID: "ev-http-1", Type: "http", Timestamp: t0, PID: 400, Domain: "api.example", Fields: map[string]any{
			"method": "POST", "url": "https://api.example/v1/x", "host": "api.example",
			"user_agent": "agentsh/1.0", "http_version": "1.1",
			"status_code": 200, "response_bytes": 1024,
		}},
		{ID: "ev-net-http-req-1", Type: "net_http_request", Timestamp: t0, PID: 401, Domain: "raw.example",
			Fields: map[string]any{"method": "GET", "url": "https://raw.example/file"}},
		{ID: "ev-http-svc-denied-1", Type: "http_service_denied_direct", Timestamp: t0, PID: 402, Domain: "blocked.example",
			Fields: map[string]any{"method": "POST", "url": "https://blocked.example/api"},
			Policy: &types.PolicyInfo{Decision: "deny", EffectiveDecision: "deny", Rule: "no-direct"}},
	}
}
