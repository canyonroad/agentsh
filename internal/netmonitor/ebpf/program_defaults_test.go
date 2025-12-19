package ebpf

import "testing"

func TestEmbeddedMapDefaults(t *testing.T) {
	def, err := EmbeddedMapDefaults()
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if def.Allow == 0 || def.Deny == 0 || def.LPM == 0 || def.LPMDeny == 0 || def.Default == 0 {
		t.Fatalf("unexpected zero defaults: %+v", def)
	}
}
