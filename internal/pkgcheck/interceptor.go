package pkgcheck

import (
	"path/filepath"
	"strings"
)

// InstallIntent captures the parsed intent of an install command.
type InstallIntent struct {
	Tool        string    // tool name (npm, pnpm, yarn, pip, uv, poetry)
	Ecosystem   Ecosystem // npm or pypi
	Packages    []string  // package names/specs from args
	BulkInstall bool      // true for "npm ci", "pip install -r", etc.
	OrigCommand string    // original command path
	OrigArgs    []string  // original args
}

// flagsWithValues lists flags that consume the next argument as a value.
// This is shared across package managers to skip flag values during package extraction.
var flagsWithValues = map[string]bool{
	"--registry":        true,
	"--save-prefix":     true,
	"--tag":             true,
	"--cache":           true,
	"--prefix":          true,
	"--target":          true,
	"--index-url":       true,
	"--extra-index-url": true,
	"-i":                true,
	"-c":                true,
	"--constraint":      true,
	"--root":            true,
	"--python":          true,
	"--config-file":     true,
	"--group":           true,
	"-G":                true,
}

// ClassifyInstallCommand inspects a command and its arguments and returns an
// InstallIntent if the command is a recognized package install operation.
//
// Scope controls which installs are captured:
//   - "new_packages_only" (default): only commands that add new packages
//   - "all_installs": also captures bulk installs (npm ci, pip install -r, etc.)
//
// Returns nil if the command is not a recognized install.
func ClassifyInstallCommand(command string, args []string, scope string) *InstallIntent {
	if scope == "" {
		scope = "new_packages_only"
	}

	base := filepath.Base(command)
	// On non-Windows systems, filepath.Base won't split on '\',
	// so also check for a backslash separator for cross-platform safety.
	if idx := strings.LastIndex(base, `\`); idx >= 0 {
		base = base[idx+1:]
	}
	// Strip .exe suffix for Windows compatibility.
	base = strings.TrimSuffix(base, ".exe")

	switch base {
	case "npm":
		return classifyNPM(command, args, scope)
	case "pnpm":
		return classifyPNPM(command, args, scope)
	case "yarn":
		return classifyYarn(command, args, scope)
	case "pip", "pip3":
		return classifyPip(command, args, scope)
	case "uv":
		return classifyUV(command, args, scope)
	case "poetry":
		return classifyPoetry(command, args, scope)
	default:
		return nil
	}
}

// classifyNPM handles npm install/i/add/ci commands.
func classifyNPM(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub := args[0]
	remaining := args[1:]

	switch sub {
	case "install", "i", "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		// "npm install" with no package args is a bulk install
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "ci":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// classifyPNPM handles pnpm add/install/i commands.
func classifyPNPM(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub := args[0]
	remaining := args[1:]

	switch sub {
	case "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "install", "i":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// classifyYarn handles yarn add/install commands.
func classifyYarn(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub := args[0]
	remaining := args[1:]

	switch sub {
	case "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "install":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// classifyPip handles pip/pip3 install commands.
func classifyPip(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	if args[0] != "install" {
		return nil
	}

	remaining := args[1:]

	// Check for -r / --requirement flag (bulk install from requirements file)
	if hasFlag(remaining, "-r") || hasFlag(remaining, "--requirement") {
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil
	}

	pkgs := extractPackages(remaining)
	if len(pkgs) > 0 {
		return &InstallIntent{
			Tool:        "pip",
			Ecosystem:   EcosystemPyPI,
			Packages:    pkgs,
			BulkInstall: false,
			OrigCommand: command,
			OrigArgs:    args,
		}
	}

	return nil
}

// classifyUV handles uv pip install and uv add commands.
func classifyUV(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	// "uv pip install ..."
	if args[0] == "pip" && len(args) > 1 && args[1] == "install" {
		remaining := args[2:]

		// Check for -r / --requirement flag
		if hasFlag(remaining, "-r") || hasFlag(remaining, "--requirement") {
			if scope == "all_installs" {
				return &InstallIntent{
					Tool:        "uv",
					Ecosystem:   EcosystemPyPI,
					BulkInstall: true,
					OrigCommand: command,
					OrigArgs:    args,
				}
			}
			return nil
		}

		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}

		// "uv pip install" with no args is bulk
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil
	}

	// "uv add ..."
	if args[0] == "add" {
		remaining := args[1:]
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil
	}

	return nil
}

// classifyPoetry handles poetry add/install commands.
func classifyPoetry(command string, args []string, scope string) *InstallIntent {
	if len(args) == 0 {
		return nil
	}

	sub := args[0]
	remaining := args[1:]

	switch sub {
	case "add":
		pkgs := extractPackages(remaining)
		if len(pkgs) > 0 {
			return &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				Packages:    pkgs,
				BulkInstall: false,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	case "install":
		if scope == "all_installs" {
			return &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: command,
				OrigArgs:    args,
			}
		}
		return nil

	default:
		return nil
	}
}

// extractPackages filters args to return only package names/specs,
// skipping flags and their values.
func extractPackages(args []string) []string {
	var pkgs []string
	skipNext := false

	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}

		if strings.HasPrefix(arg, "-") {
			// Check if this flag consumes the next arg
			// Handle --flag=value form
			if strings.Contains(arg, "=") {
				continue
			}
			if flagsWithValues[arg] {
				skipNext = true
			}
			continue
		}

		pkgs = append(pkgs, arg)
	}

	return pkgs
}

// hasFlag reports whether the given flag appears in args.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
