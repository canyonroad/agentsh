package provider

import (
	"context"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

type chainguardStub struct{}

// NewChainguardProvider returns a stub that documents the v2 deferral.
// Replace with a real implementation once Chainguard publishes the catalog
// format and grants beta access.
func NewChainguardProvider() skillcheck.CheckProvider { return &chainguardStub{} }

func (chainguardStub) Name() string                           { return "chainguard" }
func (chainguardStub) Capabilities() []skillcheck.FindingType { return nil }

func (chainguardStub) Scan(ctx context.Context, req skillcheck.ScanRequest) (*skillcheck.ScanResponse, error) {
	return &skillcheck.ScanResponse{
		Provider: "chainguard",
		Metadata: skillcheck.ResponseMetadata{
			Error: "chainguard: not yet implemented (beta access pending)",
		},
	}, nil
}
