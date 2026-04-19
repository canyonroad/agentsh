// Command gen-wire-goldens regenerates wire-format goldens for WTP messages.
//
// CI does NOT run this tool — it only verifies the existing goldens
// round-trip cleanly (TestWireGoldens_RoundTrip in
// proto/canyonroad/wtp/v1/wire_roundtrip_test.go) and that the generator
// still produces them byte-for-byte (TestWireGoldens_GeneratorReproducible).
//
// Run manually after intentional schema changes:
//
//	go run ./internal/store/watchtower/cmd/gen-wire-goldens
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/store/watchtower/cmd/gen-wire-goldens/fixtures"
	"google.golang.org/protobuf/proto"
)

const outDir = "proto/canyonroad/wtp/v1/testdata"

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail(err)
	}
	for _, f := range fixtures.All() {
		b, err := proto.Marshal(f.Message)
		if err != nil {
			fail(err)
		}
		p := filepath.Join(outDir, f.Name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fail(err)
		}
		fmt.Println("wrote", p, len(b), "bytes")
	}
	fmt.Println("regenerated goldens in", outDir)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
