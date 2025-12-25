//go:build windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WindowsShimStrategy defines the strategy for shell shimming on Windows.
type WindowsShimStrategy string

const (
	// StrategyPSProfile adds hooks to PowerShell profile.
	StrategyPSProfile WindowsShimStrategy = "psprofile"

	// StrategyWrapper creates wrapper executables in PATH.
	StrategyWrapper WindowsShimStrategy = "wrapper"
)

// WindowsShimConfig configures Windows shell shim installation.
type WindowsShimConfig struct {
	Strategy      WindowsShimStrategy
	AgentshBinary string
}

// psProfileHookMarkerStart is used to identify our additions.
const psProfileHookMarkerStart = "# >>> agentsh PowerShell integration >>>"
const psProfileHookMarkerEnd = "# <<< agentsh PowerShell integration <<<"

// GetPowerShellProfilePath returns the path to the current user's PowerShell profile.
func GetPowerShellProfilePath() (string, error) {
	// PowerShell Core (pwsh) profile location
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}

	// Try PowerShell Core first (cross-platform)
	pwshProfile := filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1")

	// Fallback to Windows PowerShell
	winPSProfile := filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")

	// Check if PowerShell Core directory exists
	if _, err := os.Stat(filepath.Dir(pwshProfile)); err == nil {
		return pwshProfile, nil
	}

	// Use Windows PowerShell location
	return winPSProfile, nil
}

// InstallWindowsPSProfile adds agentsh integration to PowerShell profile.
func InstallWindowsPSProfile(cfg WindowsShimConfig) error {
	if cfg.AgentshBinary == "" {
		cfg.AgentshBinary = "agentsh"
	}

	profilePath, err := GetPowerShellProfilePath()
	if err != nil {
		return err
	}

	// Ensure profile directory exists
	if err := os.MkdirAll(filepath.Dir(profilePath), 0o755); err != nil {
		return fmt.Errorf("create profile dir: %w", err)
	}

	hook := fmt.Sprintf(`%s
# agentsh PowerShell integration
# When AGENTSH_ENABLED is set, commands are routed through agentsh

if ($env:AGENTSH_ENABLED -and -not $env:AGENTSH_INSIDE) {
    $env:AGENTSH_INSIDE = "1"

    # Function to execute commands via agentsh
    function Invoke-AgentshCommand {
        param([string]$Command)
        & %s exec $env:AGENTSH_SESSION -- powershell -Command $Command
    }
    Set-Alias -Name ash -Value Invoke-AgentshCommand -Scope Global

    # If session is set, attach to it
    if ($env:AGENTSH_SESSION) {
        Write-Host "agentsh: attached to session $env:AGENTSH_SESSION" -ForegroundColor Cyan
    }
}
%s
`, psProfileHookMarkerStart, cfg.AgentshBinary, psProfileHookMarkerEnd)

	return appendIfMissingPS(profilePath, hook)
}

// UninstallWindowsPSProfile removes agentsh integration from PowerShell profile.
func UninstallWindowsPSProfile() error {
	profilePath, err := GetPowerShellProfilePath()
	if err != nil {
		return err
	}

	return removeHookFromFilePS(profilePath)
}

// appendIfMissingPS appends content to PowerShell profile if marker is not present.
func appendIfMissingPS(path, content string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if strings.Contains(string(existing), psProfileHookMarkerStart) {
		// Already installed
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Add newlines before our content
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		if _, err := f.WriteString("\r\n"); err != nil {
			return err
		}
	}

	_, err = f.WriteString("\r\n" + content + "\r\n")
	return err
}

// removeHookFromFilePS removes our hook block from a PowerShell file.
func removeHookFromFilePS(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Handle both Windows and Unix line endings
	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var result []string
	inBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == strings.TrimSpace(psProfileHookMarkerStart) {
			inBlock = true
			continue
		}
		if trimmed == strings.TrimSpace(psProfileHookMarkerEnd) {
			inBlock = false
			continue
		}
		if !inBlock {
			result = append(result, line)
		}
	}

	// Use Windows line endings
	return os.WriteFile(path, []byte(strings.Join(result, "\r\n")), 0o644)
}

// InstallWindowsWrapper creates wrapper batch files in a PATH directory.
func InstallWindowsWrapper(cfg WindowsShimConfig) error {
	if cfg.AgentshBinary == "" {
		cfg.AgentshBinary = "agentsh"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	wrapperDir := filepath.Join(home, ".agentsh", "bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		return fmt.Errorf("create wrapper dir: %w", err)
	}

	// Create wrapper for cmd.exe
	cmdWrapper := filepath.Join(wrapperDir, "cmd.bat")
	cmdScript := fmt.Sprintf(`@echo off
REM agentsh cmd.exe wrapper
IF NOT DEFINED AGENTSH_SESSION (
    %%SystemRoot%%\System32\cmd.exe %%*
) ELSE (
    %s exec %%AGENTSH_SESSION%% -- %%SystemRoot%%\System32\cmd.exe %%*
)
`, cfg.AgentshBinary)

	if err := os.WriteFile(cmdWrapper, []byte(cmdScript), 0o755); err != nil {
		return fmt.Errorf("write cmd wrapper: %w", err)
	}

	// Create wrapper for PowerShell
	psWrapper := filepath.Join(wrapperDir, "powershell.bat")
	psScript := fmt.Sprintf(`@echo off
REM agentsh PowerShell wrapper
IF NOT DEFINED AGENTSH_SESSION (
    powershell.exe %%*
) ELSE (
    %s exec %%AGENTSH_SESSION%% -- powershell.exe %%*
)
`, cfg.AgentshBinary)

	if err := os.WriteFile(psWrapper, []byte(psScript), 0o755); err != nil {
		return fmt.Errorf("write powershell wrapper: %w", err)
	}

	return nil
}

// UninstallWindowsWrapper removes the wrapper directory.
func UninstallWindowsWrapper() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	wrapperDir := filepath.Join(home, ".agentsh", "bin")
	return os.RemoveAll(wrapperDir)
}

// GetWindowsWrapperInstruction returns the instruction for adding wrappers to PATH.
func GetWindowsWrapperInstruction() string {
	home, _ := os.UserHomeDir()
	wrapperDir := filepath.Join(home, ".agentsh", "bin")
	return fmt.Sprintf(`# Add to your PATH environment variable:
# %s

# Or run this in PowerShell (admin):
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";%s", "User")
`, wrapperDir, wrapperDir)
}

// WindowsShimStatus reports the status of Windows shim installation.
type WindowsShimStatus struct {
	PSProfileInstalled bool   `json:"psprofile_installed"`
	PSProfilePath      string `json:"psprofile_path"`
	WrapperInstalled   bool   `json:"wrapper_installed"`
	WrapperDir         string `json:"wrapper_dir"`
	WrapperInPath      bool   `json:"wrapper_in_path"`
}

// GetWindowsShimStatus checks the current installation status.
func GetWindowsShimStatus() (*WindowsShimStatus, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	status := &WindowsShimStatus{
		WrapperDir: filepath.Join(home, ".agentsh", "bin"),
	}

	// Check PowerShell profile
	profilePath, err := GetPowerShellProfilePath()
	if err == nil {
		status.PSProfilePath = profilePath
		if content, err := os.ReadFile(profilePath); err == nil {
			status.PSProfileInstalled = strings.Contains(string(content), psProfileHookMarkerStart)
		}
	}

	// Check wrapper installation
	if _, err := os.Stat(status.WrapperDir); err == nil {
		status.WrapperInstalled = true
	}

	// Check if wrapper dir is in PATH
	pathEnv := os.Getenv("PATH")
	status.WrapperInPath = strings.Contains(strings.ToLower(pathEnv), strings.ToLower(status.WrapperDir))

	return status, nil
}
