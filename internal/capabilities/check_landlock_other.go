//go:build !linux

package capabilities

// LandlockResult holds the result of Landlock availability detection.
type LandlockResult struct {
	Available      bool
	ABI            int
	NetworkSupport bool
	Error          string
}

func (r LandlockResult) String() string {
	return "Landlock: unavailable (not Linux)"
}

// DetectLandlock returns unavailable on non-Linux platforms.
func DetectLandlock() LandlockResult {
	return LandlockResult{
		Available: false,
		Error:     "Landlock is only available on Linux",
	}
}
