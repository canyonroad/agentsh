package wtpv1_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/cmd/gen-wire-goldens/fixtures"
	"google.golang.org/protobuf/proto"
)

func TestWireGoldens_GeneratorReproducible(t *testing.T) {
	for _, f := range fixtures.All() {
		t.Run(f.Name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", f.Name))
			if err != nil {
				t.Fatalf("read golden %s: %v", f.Name, err)
			}
			got, err := proto.Marshal(f.Message)
			if err != nil {
				t.Fatalf("marshal fixture %s: %v", f.Name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("generator output drifted from golden %s\n  generator produced %d bytes\n  golden has        %d bytes\n  re-run: go run ./internal/store/watchtower/cmd/gen-wire-goldens",
					f.Name, len(got), len(want))
			}
		})
	}
}

// TestWireGoldens_NoOrphanGoldens guards against fixture set drift in the
// other direction: a stale .bin file lingering in testdata/ after the
// fixture that produced it was renamed or removed. Together with
// TestWireGoldens_GeneratorReproducible (byte-equality for known fixtures)
// it makes the fixture set authoritatively defined by fixtures.All().
func TestWireGoldens_NoOrphanGoldens(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata dir: %v", err)
	}

	wantNames := map[string]bool{}
	for _, f := range fixtures.All() {
		wantNames[f.Name] = true
	}

	gotNames := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		gotNames[e.Name()] = true
		if !wantNames[e.Name()] {
			t.Errorf("orphan golden %q in testdata/ has no fixture in fixtures.All() — remove it or add a fixture", e.Name())
		}
	}

	for name := range wantNames {
		if !gotNames[name] {
			t.Errorf("fixture %q has no checked-in golden — run: go run ./internal/store/watchtower/cmd/gen-wire-goldens", name)
		}
	}
}
