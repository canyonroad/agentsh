package awssm

import (
	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

// Config configures the AWS Secrets Manager provider.
//
// Config satisfies secrets.ProviderConfig by embedding
// secrets.ProviderConfigMarker.
type Config struct {
	secrets.ProviderConfigMarker

	// Region is the AWS region to use (e.g. "us-east-1"). Required.
	Region string
}

// TypeName returns "aws-sm". Used by the registry to map aws-sm://
// URI scheme refs to this provider.
func (Config) TypeName() string { return "aws-sm" }

// Compile-time assertions.
var (
	_ secrets.ProviderConfig = Config{}
	_ secrets.SecretProvider = (*Provider)(nil)
)
