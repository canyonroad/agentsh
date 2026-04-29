package provider

import (
	"context"

	"github.com/agentsh/agentsh/internal/skillcheck"
)

type repelloStub struct{}

// NewRepelloProvider returns a stub that documents the v2 deferral.
// Replace with a real implementation once Repello publishes a documented
// REST API for SkillCheck.
func NewRepelloProvider() skillcheck.CheckProvider { return &repelloStub{} }

func (repelloStub) Name() string                           { return "repello" }
func (repelloStub) Capabilities() []skillcheck.FindingType { return nil }

func (repelloStub) Scan(ctx context.Context, req skillcheck.ScanRequest) (*skillcheck.ScanResponse, error) {
	return &skillcheck.ScanResponse{
		Provider: "repello",
		Metadata: skillcheck.ResponseMetadata{
			Error: "repello: not yet implemented (REST API pending)",
		},
	}, nil
}
