//go:build !linux && !darwin && !windows

package capabilities

import "fmt"

// Detect returns an error on unsupported platforms.
func Detect() (*DetectResult, error) {
	return nil, fmt.Errorf("platform not supported for detection")
}
