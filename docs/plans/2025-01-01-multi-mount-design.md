# Multi-Mount Feature Design

**Status:** Implemented

## Overview

Enable agentsh to mount multiple filesystem paths with independent policies, allowing fine-grained control over what an agent can access. This supports scenarios like mounting an agent's config directory read-only to prevent self-modification while allowing read-write access to a workspace.

## 1. Configuration Schema

Mount profiles are defined in the server config (`config.yaml`):

```yaml
mount_profiles:
  claude-agent:
    base_policy: "default"
    mounts:
      - path: "/home/user/workspace"
        policy: "workspace-rw"
      - path: "/home/user/.claude"
        policy: "config-readonly"
      - path: "/home/user/.config/claude-code"
        policy: "config-readonly"

  restricted-agent:
    base_policy: "minimal"
    mounts:
      - path: "/project"
        policy: "project-only"
```

Each mount references a policy file in the policies directory:

```yaml
# configs/policies/workspace-rw.yaml
version: 1
name: workspace-rw
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: [read, write, create, delete]
    decision: allow

# configs/policies/config-readonly.yaml
version: 1
name: config-readonly
file_rules:
  - name: readonly
    paths: ["/**"]
    operations: [read, stat, list]
    decision: allow
  - name: deny-write
    paths: ["/**"]
    operations: [write, create, delete]
    decision: deny
```

## 2. Policy Evaluation Model

The evaluation follows a **restriction-only** model where mount policies can only restrict what the base policy allows:

```
For any file operation:
1. Find which mount covers this path (if any)
2. If no mount covers path → DENY (unmounted paths denied by default)
3. If mount exists:
   a. Check mount's policy → if DENY → DENY
   b. Check base policy → if DENY → DENY
   c. Otherwise → ALLOW
```

Key principles:
- **Mount policy restricts first**: A mount policy cannot grant permissions the base policy denies
- **Base policy always checked**: Even if mount allows, base policy can still deny
- **Unmounted paths denied**: Any path not covered by a mount is automatically denied
- **Most restrictive wins**: If either policy denies, the operation is denied

Example flow:
```
Agent tries to write /home/user/.claude/settings.json

1. Find mount: /home/user/.claude → config-readonly policy
2. Check config-readonly: write to /** → DENY
3. Result: DENY (mount policy blocked it)

Agent tries to read /home/user/workspace/file.txt

1. Find mount: /home/user/workspace → workspace-rw policy
2. Check workspace-rw: read /** → ALLOW
3. Check base policy: read → ALLOW
4. Result: ALLOW

Agent tries to read /etc/passwd

1. Find mount: no mount covers /etc/passwd
2. Result: DENY (unmounted path)
```

## 3. API Changes

The API remains backward compatible. The `profile` parameter is optional.

### Create Session

```
POST /api/v1/sessions
{
  "workspace": "/home/user/workspace",
  "policy": "default",
  "profile": "claude-agent"  // NEW: optional
}
```

Behavior:
- If `profile` omitted: Single mount at `workspace` using `policy` (current behavior)
- If `profile` provided: Multiple mounts per profile, `policy` field ignored (or error if both specified)

### List Profiles

```
GET /api/v1/profiles

Response:
{
  "profiles": [
    {
      "name": "claude-agent",
      "base_policy": "default",
      "mounts": [
        {"path": "/home/user/workspace", "policy": "workspace-rw"},
        {"path": "/home/user/.claude", "policy": "config-readonly"}
      ]
    }
  ]
}
```

### Session Info

```
GET /api/v1/sessions/{id}

Response:
{
  "id": "session-xxx",
  "profile": "claude-agent",  // NEW: null if using legacy single-mount
  "mounts": [                 // NEW: array of active mounts
    {"path": "/home/user/workspace", "policy": "workspace-rw"},
    {"path": "/home/user/.claude", "policy": "config-readonly"}
  ],
  // ... existing fields
}
```

## 4. Internal Architecture

### New Types

```go
// MountProfile defines a collection of mounts with policies
type MountProfile struct {
    Name       string      `yaml:"name"`
    BasePolicy string      `yaml:"base_policy"`
    Mounts     []MountSpec `yaml:"mounts"`
}

// MountSpec defines a single mount point
type MountSpec struct {
    Path   string `yaml:"path"`   // Absolute path to mount
    Policy string `yaml:"policy"` // Policy name for this mount
}

// ResolvedMount is a MountSpec with loaded policy
type ResolvedMount struct {
    MountSpec
    PolicyEngine *policy.Engine  // Loaded policy for this mount
    FSMount      *fuse.FSMount   // Active FUSE mount
}
```

### Session Changes

```go
type Session struct {
    // ... existing fields

    // Legacy single-mount (backward compat)
    Workspace string
    Policy    string

    // Multi-mount
    Profile       string           // Profile name, empty if legacy
    Mounts        []ResolvedMount  // Active mounts
    BasePolicyEng *policy.Engine   // Base policy engine
}

// FindMount returns the mount covering a path, or nil
func (s *Session) FindMount(path string) *ResolvedMount {
    // Longest prefix match
    var best *ResolvedMount
    for i := range s.Mounts {
        if strings.HasPrefix(path, s.Mounts[i].Path) {
            if best == nil || len(s.Mounts[i].Path) > len(best.Path) {
                best = &s.Mounts[i]
            }
        }
    }
    return best
}
```

### Policy Evaluation

```go
func (s *Session) CheckFileAccess(path string, op FileOp) Decision {
    mount := s.FindMount(path)
    if mount == nil {
        return Deny("path not covered by any mount")
    }

    // Check mount policy first (restriction layer)
    if d := mount.PolicyEngine.CheckFile(path, op); d.IsDeny() {
        return d
    }

    // Check base policy (always applied)
    return s.BasePolicyEng.CheckFile(path, op)
}
```

## 5. Built-in System Mounts

Certain system paths are implicitly mounted read-only without explicit configuration:

```go
var builtinSystemMounts = []MountSpec{
    // Binaries and libraries (needed to run commands)
    {Path: "/usr", Policy: "system-readonly"},
    {Path: "/lib", Policy: "system-readonly"},
    {Path: "/lib64", Policy: "system-readonly"},
    {Path: "/bin", Policy: "system-readonly"},
    {Path: "/sbin", Policy: "system-readonly"},

    // Essential system files
    {Path: "/etc/hosts", Policy: "system-readonly"},
    {Path: "/etc/resolv.conf", Policy: "system-readonly"},
    {Path: "/etc/ssl/certs", Policy: "system-readonly"},
    {Path: "/etc/ca-certificates", Policy: "system-readonly"},

    // Device files (limited)
    {Path: "/dev/null", Policy: "system-readonly"},
    {Path: "/dev/zero", Policy: "system-readonly"},
    {Path: "/dev/urandom", Policy: "system-readonly"},
}
```

The `system-readonly` policy:
```yaml
version: 1
name: system-readonly
file_rules:
  - name: readonly
    paths: ["/**"]
    operations: [read, stat, list, open]
    decision: allow
```

These are:
- Always active regardless of profile
- Cannot be overridden by user configuration
- Read-only only (no write, create, delete)
- Minimal set required for command execution

## 6. Platform-Specific System Paths

Different operating systems have different system paths. The built-in mounts are platform-aware:

```go
func getSystemMounts() []MountSpec {
    switch runtime.GOOS {
    case "linux":
        return linuxSystemMounts()
    case "darwin":
        return darwinSystemMounts()
    case "windows":
        return windowsSystemMounts()
    default:
        return minimalSystemMounts()
    }
}

func linuxSystemMounts() []MountSpec {
    mounts := []MountSpec{
        {Path: "/usr", Policy: "system-readonly"},
        {Path: "/lib", Policy: "system-readonly"},
        {Path: "/lib64", Policy: "system-readonly"},
        {Path: "/bin", Policy: "system-readonly"},
        {Path: "/sbin", Policy: "system-readonly"},
        {Path: "/etc/hosts", Policy: "system-readonly"},
        {Path: "/etc/resolv.conf", Policy: "system-readonly"},
        {Path: "/etc/ssl/certs", Policy: "system-readonly"},
    }

    // Container detection
    if isRunningInContainer() {
        // Containers may have different layouts
        mounts = append(mounts, MountSpec{
            Path: "/etc/alternatives", Policy: "system-readonly",
        })
    }

    return mounts
}

func darwinSystemMounts() []MountSpec {
    return []MountSpec{
        {Path: "/usr", Policy: "system-readonly"},
        {Path: "/bin", Policy: "system-readonly"},
        {Path: "/sbin", Policy: "system-readonly"},
        {Path: "/System/Library", Policy: "system-readonly"},
        {Path: "/Library/Frameworks", Policy: "system-readonly"},
        {Path: "/etc/hosts", Policy: "system-readonly"},
        {Path: "/etc/resolv.conf", Policy: "system-readonly"},
        // Homebrew paths
        {Path: "/opt/homebrew", Policy: "system-readonly"},
        {Path: "/usr/local/Cellar", Policy: "system-readonly"},
    }
}

func windowsSystemMounts() []MountSpec {
    return []MountSpec{
        {Path: "C:\\Windows\\System32", Policy: "system-readonly"},
        {Path: "C:\\Program Files", Policy: "system-readonly"},
        {Path: "C:\\Program Files (x86)", Policy: "system-readonly"},
    }
}

func isRunningInContainer() bool {
    // Check for container indicators
    if _, err := os.Stat("/.dockerenv"); err == nil {
        return true
    }
    if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
        return strings.Contains(string(data), "docker") ||
               strings.Contains(string(data), "kubepods")
    }
    return false
}
```

### Environment-Aware Configuration

The server can detect and adapt to its environment:

```go
type Environment struct {
    OS          string // linux, darwin, windows
    InContainer bool   // Docker, Kubernetes
    InWSL       bool   // Windows Subsystem for Linux
    InDevContainer bool // VS Code dev containers
}

func DetectEnvironment() Environment {
    env := Environment{OS: runtime.GOOS}

    // Container detection
    env.InContainer = isRunningInContainer()

    // WSL detection
    if runtime.GOOS == "linux" {
        if data, err := os.ReadFile("/proc/version"); err == nil {
            env.InWSL = strings.Contains(strings.ToLower(string(data)), "microsoft")
        }
    }

    // Dev container detection
    env.InDevContainer = os.Getenv("REMOTE_CONTAINERS") != "" ||
                         os.Getenv("CODESPACES") != ""

    return env
}
```

This allows system mounts to adapt based on:
- Base operating system (Linux/macOS/Windows)
- Container environment (Docker, Kubernetes)
- Development environment (WSL, Codespaces, Dev Containers)

## Implementation Notes

### Mount Order

When creating a session with multiple mounts:
1. Create all FUSE mounts in parallel (they're independent)
2. Fail the session if any mount fails
3. Cleanup all mounts on session termination

### Overlapping Mounts

If mount paths overlap (e.g., `/home/user` and `/home/user/workspace`):
- Use longest prefix match to find the governing mount
- `/home/user/workspace/file.txt` → governed by `/home/user/workspace` mount
- `/home/user/other/file.txt` → governed by `/home/user` mount

### Profile Validation

On server startup, validate all profiles:
- All referenced policies exist
- No circular dependencies
- Mount paths are absolute
- No duplicate mount paths within a profile

### Hot Reload

When policies are hot-reloaded:
- Existing sessions keep their loaded policies
- New sessions get updated policies
- Profile changes require server restart (or explicit reload command)
