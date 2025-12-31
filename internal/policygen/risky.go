// internal/policygen/risky.go
package policygen

import (
	"path/filepath"
	"strings"
)

// builtinRisky maps command names to their risk category.
var builtinRisky = map[string]string{
	// Network-capable
	"curl":   "network",
	"wget":   "network",
	"ssh":    "network",
	"scp":    "network",
	"rsync":  "network",
	"nc":     "network",
	"netcat": "network",
	"telnet": "network",
	"ftp":    "network",
	"sftp":   "network",

	// Destructive/privileged
	"rm":    "destructive",
	"chmod": "destructive",
	"chown": "destructive",
	"sudo":  "privileged",
	"su":    "privileged",
	"doas":  "privileged",

	// Container/orchestration
	"docker":  "container",
	"podman":  "container",
	"kubectl": "orchestration",
	"helm":    "orchestration",

	// Package managers (can run arbitrary code)
	"pip":   "package",
	"pip3":  "package",
	"gem":   "package",
	"cargo": "package",
}

// IsBuiltinRisky checks if a command is in the built-in risky list.
func IsBuiltinRisky(cmd string) (bool, string) {
	// Normalize: take base name, remove extension
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))

	if reason, ok := builtinRisky[base]; ok {
		return true, reason
	}
	return false, ""
}

// RiskyDetector tracks which commands are risky based on behavior.
type RiskyDetector struct {
	observed map[string]string // command -> reason
}

// NewRiskyDetector creates a new detector.
func NewRiskyDetector() *RiskyDetector {
	return &RiskyDetector{
		observed: make(map[string]string),
	}
}

// MarkNetworkCapable marks a command as risky because it made network calls.
func (d *RiskyDetector) MarkNetworkCapable(cmd string) {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if _, exists := d.observed[base]; !exists {
		d.observed[base] = "network-observed"
	}
}

// MarkDestructive marks a command as risky because it deleted files.
func (d *RiskyDetector) MarkDestructive(cmd string) {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if _, exists := d.observed[base]; !exists {
		d.observed[base] = "destructive-observed"
	}
}

// MarkPrivileged marks a command as risky because it changed UID.
func (d *RiskyDetector) MarkPrivileged(cmd string) {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if _, exists := d.observed[base]; !exists {
		d.observed[base] = "privilege-observed"
	}
}

// IsRisky checks if a command is risky (builtin or observed).
func (d *RiskyDetector) IsRisky(cmd string) bool {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if _, ok := builtinRisky[base]; ok {
		return true
	}
	_, ok := d.observed[base]
	return ok
}

// Reason returns why a command is risky.
func (d *RiskyDetector) Reason(cmd string) string {
	base := filepath.Base(cmd)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if reason, ok := builtinRisky[base]; ok {
		return reason
	}
	if reason, ok := d.observed[base]; ok {
		return reason
	}
	return ""
}
