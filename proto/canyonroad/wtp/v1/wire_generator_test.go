package wtpv1_test

import (
	"bytes"
	"os"
	"path/filepath"
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
