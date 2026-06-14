package tor

import (
	"net"
	"testing"
)

func TestDirectoryAuthoritySeed_NonEmptyAndValid(t *testing.T) {
	seed := DirectoryAuthoritySeed()
	if len(seed) < 5 {
		t.Fatalf("expected several authority IPs, got %d", len(seed))
	}
	for _, s := range seed {
		if net.ParseIP(s) == nil {
			t.Fatalf("seed entry %q is not a valid IP", s)
		}
	}
}
