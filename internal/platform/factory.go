package platform

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// New creates the appropriate platform implementation for the current OS.
// It automatically detects the best platform mode.
func New() (Platform, error) {
	return NewWithMode(ModeAuto)
}

// NewWithMode creates a platform with a specific mode.
// Use ModeAuto to let the system choose the best implementation.
func NewWithMode(mode PlatformMode) (Platform, error) {
	if mode == ModeAuto {
		mode = detectPlatformMode()
	}

	switch mode {
	case ModeLinuxNative:
		return newLinuxPlatform()
	case ModeDarwinNative:
		return newDarwinPlatform()
	case ModeDarwinLima:
		return newDarwinLimaPlatform()
	case ModeWindowsNative:
		return newWindowsPlatform()
	case ModeWindowsWSL2:
		return newWindowsWSL2Platform()
	default:
		return nil, fmt.Errorf("unsupported platform mode: %v", mode)
	}
}

// detectPlatformMode determines the best platform mode for the current system.
func detectPlatformMode() PlatformMode {
	switch runtime.GOOS {
	case "linux":
		// Check if we're running in WSL2
		if isWSL2() {
			// WSL2 uses the Linux implementation
			return ModeLinuxNative
		}
		return ModeLinuxNative

	case "darwin":
		// macOS - use native implementation
		// TODO: Check for Lima and prefer it if available
		return ModeDarwinNative

	case "windows":
		// Check if WSL2 is available and preferred
		if isWSL2Available() {
			return ModeWindowsWSL2
		}
		return ModeWindowsNative

	default:
		// Unknown OS - try Linux as fallback
		return ModeLinuxNative
	}
}

// isWSL2 checks if we're running inside WSL2.
func isWSL2() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

// isWSL2Available checks if WSL2 is available on Windows.
// This is called from Windows to check if WSL2 can be used.
func isWSL2Available() bool {
	// This would be implemented in windows-specific code
	// For now, return false as a stub
	return false
}

// Detect returns information about the current platform without creating it.
// Useful for capability checking before initialization.
func Detect() (PlatformMode, Capabilities, error) {
	mode := detectPlatformMode()

	// Create a temporary platform to get capabilities
	plat, err := NewWithMode(mode)
	if err != nil {
		return mode, Capabilities{}, err
	}

	caps := plat.Capabilities()

	// Clean up - don't leave resources allocated
	// (Platform hasn't been initialized, so just discard)

	return mode, caps, nil
}

// MustNew is like New but panics on error.
// Useful in tests and initialization code.
func MustNew() Platform {
	p, err := New()
	if err != nil {
		panic(fmt.Sprintf("platform.New: %v", err))
	}
	return p
}

// MustNewWithMode is like NewWithMode but panics on error.
func MustNewWithMode(mode PlatformMode) Platform {
	p, err := NewWithMode(mode)
	if err != nil {
		panic(fmt.Sprintf("platform.NewWithMode(%v): %v", mode, err))
	}
	return p
}

// Platform constructor functions - implemented in platform-specific files.
// These are variables so they can be set by build-tag-specific files.

var (
	newLinuxPlatform       func() (Platform, error)
	newDarwinPlatform      func() (Platform, error)
	newDarwinLimaPlatform  func() (Platform, error)
	newWindowsPlatform     func() (Platform, error)
	newWindowsWSL2Platform func() (Platform, error)
)

// Registration functions for platform-specific packages to call in their init().

// RegisterLinux registers the Linux platform constructor.
func RegisterLinux(constructor func() (Platform, error)) {
	newLinuxPlatform = constructor
}

// RegisterDarwin registers the macOS platform constructor.
func RegisterDarwin(constructor func() (Platform, error)) {
	newDarwinPlatform = constructor
}

// RegisterDarwinLima registers the macOS+Lima platform constructor.
func RegisterDarwinLima(constructor func() (Platform, error)) {
	newDarwinLimaPlatform = constructor
}

// RegisterWindows registers the Windows platform constructor.
func RegisterWindows(constructor func() (Platform, error)) {
	newWindowsPlatform = constructor
}

// RegisterWindowsWSL2 registers the Windows+WSL2 platform constructor.
func RegisterWindowsWSL2(constructor func() (Platform, error)) {
	newWindowsWSL2Platform = constructor
}

// platformNotImplemented returns an error for unimplemented platforms.
func platformNotImplemented(name string) (Platform, error) {
	return nil, fmt.Errorf("platform %q not implemented on %s/%s", name, runtime.GOOS, runtime.GOARCH)
}

// init sets up fallback implementations for platforms that aren't compiled in.
func init() {
	if newLinuxPlatform == nil {
		newLinuxPlatform = func() (Platform, error) {
			return platformNotImplemented("linux")
		}
	}
	if newDarwinPlatform == nil {
		newDarwinPlatform = func() (Platform, error) {
			return platformNotImplemented("darwin")
		}
	}
	if newDarwinLimaPlatform == nil {
		newDarwinLimaPlatform = func() (Platform, error) {
			return platformNotImplemented("darwin-lima")
		}
	}
	if newWindowsPlatform == nil {
		newWindowsPlatform = func() (Platform, error) {
			return platformNotImplemented("windows")
		}
	}
	if newWindowsWSL2Platform == nil {
		newWindowsWSL2Platform = func() (Platform, error) {
			return platformNotImplemented("windows-wsl2")
		}
	}
}
