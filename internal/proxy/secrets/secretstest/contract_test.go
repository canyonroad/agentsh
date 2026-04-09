package secretstest

import (
	"testing"

	secrets "github.com/agentsh/agentsh/internal/proxy/secrets"
)

func TestProviderContract_AppliedToMemoryProvider(t *testing.T) {
	mp := NewMemoryProvider("contract-target", nil)
	probeRef := secrets.SecretRef{
		Scheme: "keyring",
		Host:   "agentsh-contract-probe",
		Path:   "unset",
	}
	ProviderContract(t, "memory", mp, probeRef)
}
