//go:build darwin

package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DarwinShimStrategy defines the strategy for shell shimming on macOS.
type DarwinShimStrategy string

const (
	// StrategyPATH creates shims in ~/.agentsh/bin that must be added to PATH.
	StrategyPATH DarwinShimStrategy = "path"

	// StrategyProfile adds hooks to shell profile files (.zshrc, .bashrc).
	StrategyProfile DarwinShimStrategy = "profile"
)

// DarwinShimConfig configures macOS shell shim installation.
type DarwinShimConfig struct {
	// Strategy selects how to install the shim
	Strategy DarwinShimStrategy

	// AgentshBinary is the path to the agentsh binary
	AgentshBinary string

	// Shells to shim (for PATH strategy)
	Shells []string

	// ProfilePaths to modify (for profile strategy)
	// If empty, defaults are used based on detected shells
	ProfilePaths []string
}

// DefaultDarwinShells returns the default shells to shim on macOS.
func DefaultDarwinShells() []string {
	return []string{"sh", "bash", "zsh", "dash"}
}

// InstallDarwinPATH creates wrapper scripts in ~/.agentsh/bin for each shell.
// Users must add ~/.agentsh/bin to their PATH.
func InstallDarwinPATH(cfg DarwinShimConfig) error {
	if cfg.AgentshBinary == "" {
		cfg.AgentshBinary = "agentsh"
	}
	if len(cfg.Shells) == 0 {
		cfg.Shells = DefaultDarwinShells()
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	shimDir := filepath.Join(home, ".agentsh", "bin")
	if err := os.MkdirAll(shimDir, 0o755); err != nil {
		return fmt.Errorf("create shim dir: %w", err)
	}

	for _, shell := range cfg.Shells {
		shimPath := filepath.Join(shimDir, shell)
		script := fmt.Sprintf(`#!/bin/bash
# agentsh shell shim for %s
# This wrapper routes shell commands through agentsh for policy enforcement.

# Find the real shell
REAL_SHELL=""
for candidate in /bin/%s /usr/bin/%s /opt/homebrew/bin/%s; do
    if [ -x "$candidate" ] && [ "$candidate" != "$0" ]; then
        REAL_SHELL="$candidate"
        break
    fi
done

if [ -z "$REAL_SHELL" ]; then
    echo "agentsh: cannot find real %s binary" >&2
    exit 1
fi

# If agentsh is not active, pass through to real shell
if [ -z "$AGENTSH_SESSION" ] && [ -z "$AGENTSH_ENABLED" ]; then
    exec "$REAL_SHELL" "$@"
fi

# Route through agentsh
exec %s shim-exec "$REAL_SHELL" "$@"
`, shell, shell, shell, shell, shell, cfg.AgentshBinary)

		if err := os.WriteFile(shimPath, []byte(script), 0o755); err != nil {
			return fmt.Errorf("write shim %s: %w", shimPath, err)
		}
	}

	return nil
}

// UninstallDarwinPATH removes the shim directory.
func UninstallDarwinPATH() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	shimDir := filepath.Join(home, ".agentsh", "bin")
	if err := os.RemoveAll(shimDir); err != nil {
		return fmt.Errorf("remove shim dir: %w", err)
	}

	return nil
}

// GetDarwinPATHInstruction returns the instruction for adding shims to PATH.
func GetDarwinPATHInstruction() string {
	return `# Add to your shell profile (~/.zshrc or ~/.bashrc):
export PATH="$HOME/.agentsh/bin:$PATH"`
}

// ProfileHookConfig configures profile hook installation.
type ProfileHookConfig struct {
	// Zsh installs hook to ~/.zshrc
	Zsh bool

	// Bash installs hook to ~/.bashrc and ~/.bash_profile
	Bash bool
}

// profileHookMarkerStart is used to identify our additions.
const profileHookMarkerStart = "# >>> agentsh shell integration >>>"
const profileHookMarkerEnd = "# <<< agentsh shell integration <<<"

// InstallDarwinProfileHook adds agentsh integration to shell profile files.
func InstallDarwinProfileHook(cfg ProfileHookConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	hook := fmt.Sprintf(`%s
# When AGENTSH_ENABLED is set, wrap the shell session
if [[ -z "$AGENTSH_INSIDE" && -n "$AGENTSH_ENABLED" ]]; then
    export AGENTSH_INSIDE=1
    if [[ -n "$AGENTSH_SESSION" ]]; then
        exec agentsh session attach "$AGENTSH_SESSION"
    fi
fi
%s
`, profileHookMarkerStart, profileHookMarkerEnd)

	if cfg.Zsh {
		zshrc := filepath.Join(home, ".zshrc")
		if err := appendIfMissing(zshrc, hook); err != nil {
			return fmt.Errorf("install zsh hook: %w", err)
		}
	}

	if cfg.Bash {
		bashrc := filepath.Join(home, ".bashrc")
		if err := appendIfMissing(bashrc, hook); err != nil {
			return fmt.Errorf("install bashrc hook: %w", err)
		}

		bashProfile := filepath.Join(home, ".bash_profile")
		if err := appendIfMissing(bashProfile, hook); err != nil {
			return fmt.Errorf("install bash_profile hook: %w", err)
		}
	}

	return nil
}

// UninstallDarwinProfileHook removes agentsh integration from shell profiles.
func UninstallDarwinProfileHook(cfg ProfileHookConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	if cfg.Zsh {
		zshrc := filepath.Join(home, ".zshrc")
		if err := removeHookFromFile(zshrc); err != nil {
			return fmt.Errorf("remove zsh hook: %w", err)
		}
	}

	if cfg.Bash {
		bashrc := filepath.Join(home, ".bashrc")
		if err := removeHookFromFile(bashrc); err != nil {
			return fmt.Errorf("remove bashrc hook: %w", err)
		}

		bashProfile := filepath.Join(home, ".bash_profile")
		if err := removeHookFromFile(bashProfile); err != nil {
			return fmt.Errorf("remove bash_profile hook: %w", err)
		}
	}

	return nil
}

// appendIfMissing appends content to file if our marker is not already present.
func appendIfMissing(path, content string) error {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if strings.Contains(string(existing), profileHookMarkerStart) {
		// Already installed
		return nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Add newline before our content if file doesn't end with one
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}

	_, err = f.WriteString("\n" + content + "\n")
	return err
}

// removeHookFromFile removes our hook block from a file.
func removeHookFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(content), "\n")
	var result []string
	inBlock := false

	for _, line := range lines {
		if strings.TrimSpace(line) == strings.TrimSpace(profileHookMarkerStart) {
			inBlock = true
			continue
		}
		if strings.TrimSpace(line) == strings.TrimSpace(profileHookMarkerEnd) {
			inBlock = false
			continue
		}
		if !inBlock {
			result = append(result, line)
		}
	}

	return os.WriteFile(path, []byte(strings.Join(result, "\n")), 0o644)
}

// DarwinShimStatus reports the status of macOS shim installation.
type DarwinShimStatus struct {
	PATHInstalled    bool     `json:"path_installed"`
	PATHDir          string   `json:"path_dir"`
	PATHShells       []string `json:"path_shells"`
	PATHInPath       bool     `json:"path_in_path"`
	ProfileZsh       bool     `json:"profile_zsh"`
	ProfileBash      bool     `json:"profile_bash"`
}

// GetDarwinShimStatus checks the current installation status.
func GetDarwinShimStatus() (*DarwinShimStatus, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	status := &DarwinShimStatus{
		PATHDir: filepath.Join(home, ".agentsh", "bin"),
	}

	// Check PATH-based installation
	if entries, err := os.ReadDir(status.PATHDir); err == nil {
		status.PATHInstalled = true
		for _, e := range entries {
			if !e.IsDir() {
				status.PATHShells = append(status.PATHShells, e.Name())
			}
		}
	}

	// Check if shim dir is in PATH
	pathEnv := os.Getenv("PATH")
	status.PATHInPath = strings.Contains(pathEnv, status.PATHDir)

	// Check profile hooks
	zshrc := filepath.Join(home, ".zshrc")
	if content, err := os.ReadFile(zshrc); err == nil {
		status.ProfileZsh = strings.Contains(string(content), profileHookMarkerStart)
	}

	bashrc := filepath.Join(home, ".bashrc")
	if content, err := os.ReadFile(bashrc); err == nil {
		status.ProfileBash = strings.Contains(string(content), profileHookMarkerStart)
	}

	return status, nil
}
