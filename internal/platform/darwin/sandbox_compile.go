//go:build darwin && cgo

package darwin

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/agentsh/agentsh/internal/platform/darwin/sbpl"
	"github.com/agentsh/agentsh/internal/platform/darwin/sandboxext"
	"github.com/agentsh/agentsh/internal/policy"
)

// SandboxConfig holds the compiled SBPL profile and extension tokens.
type SandboxConfig struct {
	Profile     string   // compiled SBPL string
	TokenValues []string // opaque token strings for macwrap
}

var defaultExecBlocklist = []string{
	"/usr/bin/osascript",
	"/usr/bin/security",
	"/usr/sbin/systemsetup",
	"/usr/bin/tccutil",
	"/usr/sbin/csrutil",
}

var defaultExecAllowPaths = []string{
	"/usr/bin", "/bin", "/usr/sbin", "/sbin",
	"/usr/local/bin", "/opt/homebrew/bin",
}

var defaultMachAllow = []string{
	"com.apple.system.logger",
	"com.apple.SecurityServer",
	"com.apple.distributed_notifications@Gv0",
	"com.apple.system.notification_center",
	"com.apple.CoreServices.coreservicesd",
	"com.apple.DiskArbitration.diskarbitrationd",
	"com.apple.xpc.launchd.domain.system",
}

var defaultMachBlock = []string{
	"com.apple.security.authtrampoline",
	"com.apple.coreservices.launchservicesd",
	"com.apple.securityd",
}

var defaultMachBlockPrefixes = []string{
	"com.apple.pasteboard.",
}

// CompileDarwinSandbox orchestrates the SBPL builder and token manager to
// compile a policy.Policy into a sandbox configuration with an SBPL profile
// and extension tokens.
func CompileDarwinSandbox(pol *policy.Policy, workspacePath string) (*SandboxConfig, error) {
	p := sbpl.New()
	mgr := sandboxext.NewManager()
	defer mgr.RevokeAll()

	// 1. System essentials
	p.AllowSystemEssentials()

	// 2. Workspace (full access with ioctl)
	if workspacePath != "" {
		absWs, err := filepath.Abs(workspacePath)
		if err == nil {
			workspacePath = absWs
		}
		p.AllowFileReadWriteIOctl(sbpl.Subpath, workspacePath)
		mgr.Issue(workspacePath, sandboxext.ReadWrite)
	}

	// 3. File rules from policy (only "allow" decision, deny = omission)
	for _, rule := range pol.FileRules {
		if rule.Decision != "allow" {
			continue
		}
		for _, path := range rule.Paths {
			isWrite := containsAny(rule.Operations, "write", "*", "delete")
			match := classifyPath(path)
			if isWrite {
				p.AllowFileReadWrite(match, path)
				mgr.Issue(path, sandboxext.ReadWrite)
			} else {
				p.AllowFileRead(match, path)
				mgr.Issue(path, sandboxext.ReadOnly)
			}
		}
	}

	// 4. Exec blocklist (deny before allow)
	for _, blocked := range defaultExecBlocklist {
		p.DenyProcessExec(sbpl.Literal, blocked)
	}
	// Default exec allow paths
	for _, allowPath := range defaultExecAllowPaths {
		p.AllowProcessExec(sbpl.Subpath, allowPath)
	}
	if workspacePath != "" {
		p.AllowProcessExec(sbpl.Subpath, workspacePath)
	}

	// 5. Policy command rules
	for _, rule := range pol.CommandRules {
		for _, cmd := range rule.Commands {
			switch rule.Decision {
			case "allow":
				p.AllowProcessExec(sbpl.Literal, resolveCommand(cmd))
			case "deny":
				p.DenyProcessExec(sbpl.Literal, resolveCommand(cmd))
			}
		}
	}

	// 6. Network rules
	for _, rule := range pol.NetworkRules {
		if rule.Decision != "allow" {
			continue
		}
		if len(rule.Domains) > 0 || (len(rule.Ports) == 0 && len(rule.CIDRs) == 0) {
			p.AllowNetworkAll()
			break
		}
		for _, port := range rule.Ports {
			p.AllowNetworkOutbound("tcp", fmt.Sprintf("*:%d", port))
		}
	}

	// 7. Mach services (deny first)
	for _, svc := range defaultMachBlock {
		p.DenyMachLookup(svc)
	}
	for _, prefix := range defaultMachBlockPrefixes {
		p.DenyMachLookupPrefix(prefix)
	}
	for _, svc := range defaultMachAllow {
		p.AllowMachLookup(svc)
	}

	// Build profile
	profile, err := p.Build()
	if err != nil {
		return nil, fmt.Errorf("build SBPL profile: %w", err)
	}

	return &SandboxConfig{
		Profile:     profile,
		TokenValues: mgr.TokenValues(),
	}, nil
}

// classifyPath determines the SBPL path match type based on the path pattern.
// Paths ending in /* or / are treated as subpaths (directories).
// Paths whose base name has no extension are treated as subpaths (directories).
// All others are treated as literals (exact files).
func classifyPath(path string) sbpl.PathMatch {
	if strings.HasSuffix(path, "/*") || strings.HasSuffix(path, "/") {
		return sbpl.Subpath
	}
	base := filepath.Base(path)
	if !strings.Contains(base, ".") {
		return sbpl.Subpath
	}
	return sbpl.Literal
}

// resolveCommand resolves a command name to an absolute path. If the command
// is already absolute, it is returned as-is. Otherwise, exec.LookPath is
// tried, falling back to /usr/bin/<cmd>.
func resolveCommand(cmd string) string {
	if filepath.IsAbs(cmd) {
		return cmd
	}
	if resolved, err := exec.LookPath(cmd); err == nil {
		return resolved
	}
	return "/usr/bin/" + cmd
}

// containsAny returns true if any element in slice equals any of the values.
func containsAny(slice []string, values ...string) bool {
	for _, s := range slice {
		for _, v := range values {
			if s == v {
				return true
			}
		}
	}
	return false
}
