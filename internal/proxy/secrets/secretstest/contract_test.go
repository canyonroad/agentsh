package secretstest

import "testing"

func TestProviderContract_AppliedToMemoryProvider(t *testing.T) {
	mp := NewMemoryProvider("contract-target", nil)
	ProviderContract(t, "memory", mp)
}
