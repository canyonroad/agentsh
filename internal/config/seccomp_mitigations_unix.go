//go:build linux || darwin

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

func validateMitigationPathPermissions(filePath string) error {
	dir := filepath.Dir(filePath)
	for _, path := range []string{dir, filePath} {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat mitigation path %q: %w", path, err)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("mitigation path %q is world-writable", path)
		}
	}
	return nil
}
