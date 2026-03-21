//go:build windows

package capabilities

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func buildWindowsDomains(caps map[string]any) []ProtectionDomain {
	appContainer, _ := caps["app_container"].(bool)
	winfsp, _ := caps["winfsp"].(bool)
	minifilter, _ := caps["minifilter"].(bool)
	windivert, _ := caps["windivert"].(bool)
	jobObjects, _ := caps["job_objects"].(bool)

	return []ProtectionDomain{
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "winfsp", Available: winfsp, Detail: "", Description: "filesystem interception", CheckMethod: "binary"},
				{Name: "minifilter", Available: minifilter, Detail: "", Description: "kernel file filtering", CheckMethod: "probe"},
			},
		},
		{
			Name: "Command Control", Weight: WeightCommandControl,
			Backends: []DetectedBackend{
				{Name: "app-container", Available: appContainer, Detail: "", Description: "AppContainer process isolation", CheckMethod: "probe"},
			},
		},
		{
			Name: "Network", Weight: WeightNetwork,
			Backends: []DetectedBackend{
				{Name: "windivert", Available: windivert, Detail: "", Description: "network interception", CheckMethod: "binary"},
			},
		},
		{
			Name: "Resource Limits", Weight: WeightResourceLimits,
			Backends: []DetectedBackend{
				{Name: "job-objects", Available: jobObjects, Detail: "", Description: "process resource limits", CheckMethod: "builtin"},
			},
			Active: "job-objects",
		},
		{
			Name: "Isolation", Weight: WeightIsolation,
			Backends: []DetectedBackend{
				{Name: "app-container", Available: appContainer, Detail: "", Description: "AppContainer isolation", CheckMethod: "probe"},
			},
		},
	}
}

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	caps := map[string]any{
		"app_container": checkAppContainer(),
		"winfsp":        checkWinFsp(),
		"minifilter":    checkMinifilter(),
		"windivert":     checkWinDivert(),
		"job_objects":   true, // Always available
	}

	mode, _ := selectWindowsMode(caps)
	domains := buildWindowsDomains(caps)
	score := ComputeScore(domains)

	var available, unavailable []string
	for _, d := range domains {
		for _, b := range d.Backends {
			if b.Available {
				available = append(available, b.Name)
			} else {
				unavailable = append(unavailable, b.Name)
			}
		}
	}

	tips := GenerateTipsFromDomains(domains)

	return &DetectResult{
		Platform:        "windows",
		SecurityMode:    mode,
		ProtectionScore: score,
		Domains:         domains,
		Capabilities:    caps,
		Summary:         DetectSummary{Available: available, Unavailable: unavailable},
		Tips:            tips,
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
