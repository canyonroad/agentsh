package provider

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// providerFactory builds a CheckProvider configured to talk to the given baseURL.
// Each provider's test file defines its own factory.
type providerFactory func(t *testing.T, baseURL string) pkgcheck.CheckProvider

// runContractSuite runs the shared CheckProvider contract assertions.
func runContractSuite(t *testing.T, name string, makeProvider providerFactory, fixture contractFixture) {
	t.Run(name+"/EmptyInput", func(t *testing.T) {
		p := makeProvider(t, fixture.cleanServerURL)
		resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  nil,
		})
		if err != nil {
			t.Fatalf("empty input must not error: %v", err)
		}
		if resp == nil {
			t.Fatal("response must not be nil")
		}
		if len(resp.Findings) != 0 {
			t.Fatalf("empty input should yield 0 findings, got %d", len(resp.Findings))
		}
	})

	t.Run(name+"/RespectsContextCancellation", func(t *testing.T) {
		p := makeProvider(t, fixture.slowServerURL)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, err := p.CheckBatch(ctx, pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  []pkgcheck.PackageRef{{Name: "lodash", Version: "4.17.21"}},
		})
		if err == nil {
			t.Fatal("cancelled context must produce an error")
		}
	})

	t.Run(name+"/TransportErrorReturnsError", func(t *testing.T) {
		p := makeProvider(t, "http://127.0.0.1:1") // unreachable
		_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  []pkgcheck.PackageRef{{Name: "lodash", Version: "4.17.21"}},
		})
		if err == nil {
			t.Fatal("transport error must return an error")
		}
	})
}

// contractFixture holds the test servers a provider needs to exercise the contract.
type contractFixture struct {
	cleanServerURL string // returns a 200 OK with no findings
	slowServerURL  string // sleeps longer than the test ctx timeout
}
