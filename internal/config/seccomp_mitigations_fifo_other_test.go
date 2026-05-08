//go:build !linux && !darwin

package config

import "testing"

func createExternalMitigationFIFO(t *testing.T, path string) {
	t.Helper()
	t.Skip("Unix special files are not portable to this platform")
}

func startExternalMitigationFIFOWriter(t *testing.T, path string, data []byte) func() {
	t.Helper()
	return func() {}
}
