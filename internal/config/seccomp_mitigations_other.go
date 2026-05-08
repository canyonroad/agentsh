//go:build !linux && !darwin

package config

func validateMitigationPathPermissions(filePath string) error {
	return nil
}
