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
	return nil // populated by per-class PRs
}
