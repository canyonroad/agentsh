package wtpv1

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestWireGoldens_RoundTrip(t *testing.T) {
	cases := []struct {
		file string
		make func() proto.Message
	}{
		{"compact_event.bin", func() proto.Message { return new(CompactEvent) }},
		{"event_batch.bin", func() proto.Message { return new(EventBatch) }},
		{"session_init.bin", func() proto.Message { return new(SessionInit) }},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v", path, err)
			}
			msg := tc.make()
			if err := proto.Unmarshal(data, msg); err != nil {
				t.Fatalf("unmarshal golden %s: %v", path, err)
			}
			redone, err := proto.Marshal(msg)
			if err != nil {
				t.Fatalf("re-marshal golden %s: %v", path, err)
			}
			// Protobuf re-marshal is canonical for known fields; if this fails the
			// golden contains data the proto schema cannot represent (a real
			// regression, not a stylistic difference).
			if !proto.Equal(msg, decode(t, redone, tc.make())) {
				t.Fatalf("re-marshal does not round-trip for %s", path)
			}
		})
	}
}

func decode(t *testing.T, b []byte, into proto.Message) proto.Message {
	t.Helper()
	if err := proto.Unmarshal(b, into); err != nil {
		t.Fatal(err)
	}
	return into
}
