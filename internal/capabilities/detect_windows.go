//go:build windows

package capabilities

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	caps := map[string]any{
		"app_container": checkAppContainer(),
		"winfsp":        checkWinFsp(),
		"minifilter":    checkMinifilter(),
		"windivert":     checkWinDivert(),
		"job_objects":   true, // Always available
	}

	mode, score := selectWindowsMode(caps)

	// Build summary
	var available, unavailable []string
	for k, v := range caps {
		if val, ok := v.(bool); ok {
			if val {
				available = append(available, k)
			} else {
				unavailable = append(unavailable, k)
			}
		}
	}

	tips := GenerateTips("windows", caps)

	return &DetectResult{
		Platform:        "windows",
		SecurityMode:    mode,
		ProtectionScore: score,
		Capabilities:    caps,
		Summary: DetectSummary{
			Available:   available,
			Unavailable: unavailable,
		},
		Tips: tips,
	}, nil
}

func checkAppContainer() bool {
	// AppContainer requires Windows 8+
	ver := windows.RtlGetVersion()
	// Windows 8 is version 6.2
	return ver.MajorVersion > 6 || (ver.MajorVersion == 6 && ver.MinorVersion >= 2)
}

func checkWinFsp() bool {
	// Check if WinFsp DLL exists
	programFiles := os.Getenv("ProgramFiles(x86)")
	if programFiles == "" {
		programFiles = os.Getenv("ProgramFiles")
	}
	dllPath := filepath.Join(programFiles, "WinFsp", "bin", "winfsp-x64.dll")
	_, err := os.Stat(dllPath)
	return err == nil
}

func checkMinifilter() bool {
	// Check if our minifilter driver is loaded
	// This is a simplified check - in production would query SCM
	return false
}

func checkWinDivert() bool {
	// Check if WinDivert is available
	_, err := os.Stat(`C:\Windows\System32\WinDivert.dll`)
	return err == nil
}

func selectWindowsMode(caps map[string]any) (string, int) {
	appContainer, _ := caps["app_container"].(bool)
	winfsp, _ := caps["winfsp"].(bool)
	minifilter, _ := caps["minifilter"].(bool)

	if appContainer && minifilter && winfsp {
		return "full", 90
	}
	if appContainer && winfsp {
		return "appcontainer-winfsp", 75
	}
	if appContainer {
		return "appcontainer", 65
	}
	return "job-objects", 50
}
