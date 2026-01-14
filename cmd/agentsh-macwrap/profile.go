//go:build darwin

package main

import (
	"fmt"
	"strings"
)

// generateProfile creates an SBPL profile from config.
func generateProfile(cfg *WrapperConfig) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n\n")

	// Basic process operations
	sb.WriteString(";; Basic process operations\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("(allow process-exec)\n")
	sb.WriteString("(allow signal (target self))\n")
	sb.WriteString("(allow sysctl-read)\n\n")

	// System libraries
	sb.WriteString(";; System libraries and frameworks\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/usr/lib\")\n")
	sb.WriteString("    (subpath \"/usr/share\")\n")
	sb.WriteString("    (subpath \"/System/Library\")\n")
	sb.WriteString("    (subpath \"/Library/Frameworks\")\n")
	sb.WriteString("    (subpath \"/private/var/db/dyld\")\n")
	sb.WriteString("    (literal \"/dev/null\")\n")
	sb.WriteString("    (literal \"/dev/random\")\n")
	sb.WriteString("    (literal \"/dev/urandom\")\n")
	sb.WriteString("    (literal \"/dev/zero\"))\n\n")

	// Common tools
	sb.WriteString(";; Common tool locations\n")
	sb.WriteString("(allow file-read*\n")
	sb.WriteString("    (subpath \"/usr/bin\")\n")
	sb.WriteString("    (subpath \"/usr/sbin\")\n")
	sb.WriteString("    (subpath \"/bin\")\n")
	sb.WriteString("    (subpath \"/sbin\")\n")
	sb.WriteString("    (subpath \"/usr/local/bin\")\n")
	sb.WriteString("    (subpath \"/opt/homebrew/bin\")\n")
	sb.WriteString("    (subpath \"/opt/homebrew/Cellar\"))\n\n")

	// TTY access
	sb.WriteString(";; TTY access\n")
	sb.WriteString("(allow file-read* file-write*\n")
	sb.WriteString("    (regex #\"^/dev/ttys[0-9]+$\")\n")
	sb.WriteString("    (regex #\"^/dev/pty[pqrs][0-9a-f]$\")\n")
	sb.WriteString("    (literal \"/dev/tty\"))\n\n")

	// Temp files
	sb.WriteString(";; Temporary files\n")
	sb.WriteString("(allow file-read* file-write*\n")
	sb.WriteString("    (subpath \"/private/tmp\")\n")
	sb.WriteString("    (subpath \"/tmp\")\n")
	sb.WriteString("    (subpath \"/var/folders\"))\n\n")

	// Workspace
	if cfg.WorkspacePath != "" {
		sb.WriteString(";; Workspace (full access)\n")
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* file-ioctl\n    (subpath \"%s\"))\n\n",
			escapePath(cfg.WorkspacePath)))
	}

	// Additional paths
	for _, p := range cfg.AllowedPaths {
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write*\n    (subpath \"%s\"))\n",
			escapePath(p)))
	}
	if len(cfg.AllowedPaths) > 0 {
		sb.WriteString("\n")
	}

	// Network
	if cfg.AllowNetwork {
		sb.WriteString(";; Network access\n")
		sb.WriteString("(allow network*)\n\n")
	}

	// IPC (non-mach)
	sb.WriteString(";; POSIX IPC\n")
	sb.WriteString("(allow ipc-posix*)\n\n")

	// Mach services
	sb.WriteString(";; Mach/XPC services\n")
	generateMachRules(&sb, cfg.MachServices)

	return sb.String()
}

func generateMachRules(sb *strings.Builder, cfg MachServicesConfig) {
	// Mach-register always allowed for own services
	sb.WriteString("(allow mach-register)\n\n")

	if cfg.DefaultAction == "allow" {
		// Default allow, explicit blocks
		sb.WriteString(";; Default: allow all mach-lookup\n")
		sb.WriteString("(allow mach-lookup)\n\n")

		// Block specific services
		if len(cfg.Block) > 0 || len(cfg.BlockPrefixes) > 0 {
			sb.WriteString(";; Blocked services\n")
			sb.WriteString("(deny mach-lookup\n")
			for _, svc := range cfg.Block {
				sb.WriteString(fmt.Sprintf("    (global-name %q)\n", svc))
			}
			for _, prefix := range cfg.BlockPrefixes {
				sb.WriteString(fmt.Sprintf("    (global-name-prefix %q)\n", prefix))
			}
			sb.WriteString(")\n")
		}
	} else {
		// Default deny, explicit allows
		sb.WriteString(";; Default: deny mach-lookup (allowlist mode)\n")

		// Allow specific services
		if len(cfg.Allow) > 0 || len(cfg.AllowPrefixes) > 0 {
			sb.WriteString("(allow mach-lookup\n")
			for _, svc := range cfg.Allow {
				sb.WriteString(fmt.Sprintf("    (global-name %q)\n", svc))
			}
			for _, prefix := range cfg.AllowPrefixes {
				sb.WriteString(fmt.Sprintf("    (global-name-prefix %q)\n", prefix))
			}
			sb.WriteString(")\n")
		}
	}
}

func escapePath(path string) string {
	path = strings.ReplaceAll(path, "\\", "\\\\")
	path = strings.ReplaceAll(path, "\"", "\\\"")
	return path
}
