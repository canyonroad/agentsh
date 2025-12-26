//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

// RegistryOperation represents a registry operation type.
type RegistryOperation string

const (
	RegOpQueryValue  RegistryOperation = "query_value"
	RegOpSetValue    RegistryOperation = "set_value"
	RegOpDeleteValue RegistryOperation = "delete_value"
	RegOpCreateKey   RegistryOperation = "create_key"
	RegOpDeleteKey   RegistryOperation = "delete_key"
	RegOpRenameKey   RegistryOperation = "rename_key"
	RegOpEnumKeys    RegistryOperation = "enum_keys"
	RegOpEnumValues  RegistryOperation = "enum_values"
	RegOpOpenKey     RegistryOperation = "open_key"
	RegOpCloseKey    RegistryOperation = "close_key"
)

// RegistryHive represents a Windows registry hive.
type RegistryHive string

const (
	HiveClassesRoot   RegistryHive = "HKEY_CLASSES_ROOT"
	HiveCurrentUser   RegistryHive = "HKEY_CURRENT_USER"
	HiveLocalMachine  RegistryHive = "HKEY_LOCAL_MACHINE"
	HiveUsers         RegistryHive = "HKEY_USERS"
	HiveCurrentConfig RegistryHive = "HKEY_CURRENT_CONFIG"
)

// RiskLevel represents the security risk of a registry path.
type RiskLevel int

const (
	RiskLow RiskLevel = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

// String returns the risk level as a string.
func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// RegistryPathPolicy defines policy for a registry path.
type RegistryPathPolicy struct {
	Path        string
	Risk        RiskLevel
	Description string
	Technique   string // MITRE ATT&CK technique
}

// HighRiskRegistryPaths defines paths commonly used for malicious purposes.
var HighRiskRegistryPaths = []RegistryPathPolicy{
	// Persistence - Auto-start locations
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Risk:        RiskCritical,
		Description: "Programs that run at startup for all users",
		Technique:   "T1547.001 - Registry Run Keys",
	},
	{
		Path:        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		Risk:        RiskCritical,
		Description: "Programs that run at startup for current user",
		Technique:   "T1547.001 - Registry Run Keys",
	},
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		Risk:        RiskCritical,
		Description: "Programs that run once at next startup",
		Technique:   "T1547.001 - Registry Run Keys",
	},
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		Risk:        RiskCritical,
		Description: "Winlogon process configuration (Shell, Userinit)",
		Technique:   "T1547.004 - Winlogon Helper DLL",
	},

	// Services
	{
		Path:        `HKLM\SYSTEM\CurrentControlSet\Services`,
		Risk:        RiskHigh,
		Description: "Windows services configuration",
		Technique:   "T1543.003 - Windows Service",
	},

	// Scheduled Tasks
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`,
		Risk:        RiskHigh,
		Description: "Scheduled tasks configuration",
		Technique:   "T1053.005 - Scheduled Task",
	},

	// DLL Search Order Hijacking
	{
		Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
		Risk:        RiskCritical,
		Description: "Known DLLs that Windows loads from System32",
		Technique:   "T1574.001 - DLL Search Order Hijacking",
	},

	// AppInit DLLs
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		Risk:        RiskCritical,
		Description: "AppInit_DLLs loaded into every process",
		Technique:   "T1546.010 - AppInit DLLs",
	},

	// Image File Execution Options
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		Risk:        RiskCritical,
		Description: "Debugger settings - can redirect executables",
		Technique:   "T1546.012 - Image File Execution Options",
	},

	// COM Objects
	{
		Path:        `HKLM\SOFTWARE\Classes\CLSID`,
		Risk:        RiskHigh,
		Description: "COM object registrations",
		Technique:   "T1546.015 - COM Hijacking",
	},
	{
		Path:        `HKCU\SOFTWARE\Classes\CLSID`,
		Risk:        RiskHigh,
		Description: "Per-user COM object registrations (shadows HKLM)",
		Technique:   "T1546.015 - COM Hijacking",
	},

	// Security Settings
	{
		Path:        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`,
		Risk:        RiskHigh,
		Description: "Windows policy settings",
		Technique:   "Defense Evasion",
	},
	{
		Path:        `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`,
		Risk:        RiskCritical,
		Description: "Windows Defender configuration",
		Technique:   "T1562.001 - Disable or Modify Tools",
	},

	// Firewall
	{
		Path:        `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`,
		Risk:        RiskHigh,
		Description: "Windows Firewall configuration",
		Technique:   "T1562.004 - Disable or Modify Firewall",
	},

	// LSA (Credential Access)
	{
		Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
		Risk:        RiskCritical,
		Description: "Local Security Authority settings",
		Technique:   "T1003 - Credential Dumping",
	},
	{
		Path:        `HKLM\SECURITY\Policy\Secrets`,
		Risk:        RiskCritical,
		Description: "LSA Secrets storage",
		Technique:   "T1003.004 - LSA Secrets",
	},

	// Terminal Services
	{
		Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		Risk:        RiskHigh,
		Description: "Remote Desktop settings",
		Technique:   "T1021.001 - Remote Desktop Protocol",
	},
}

// RegistryMonitor watches for registry changes on high-risk paths.
type RegistryMonitor struct {
	eventChan chan<- types.Event
	watches   map[string]*registryWatch
	watchMu   sync.RWMutex
	stopChan  chan struct{}
	wg        sync.WaitGroup
	running   bool
	mu        sync.Mutex
}

type registryWatch struct {
	path      string
	policy    *RegistryPathPolicy
	recursive bool
}

// NewRegistryMonitor creates a new Windows registry monitor.
func NewRegistryMonitor(eventChan chan<- types.Event) *RegistryMonitor {
	return &RegistryMonitor{
		eventChan: eventChan,
		watches:   make(map[string]*registryWatch),
		stopChan:  make(chan struct{}),
	}
}

// Start begins monitoring high-risk registry paths.
func (m *RegistryMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("registry monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	// Set up watches for high-risk paths
	for i := range HighRiskRegistryPaths {
		policy := &HighRiskRegistryPaths[i]
		if err := m.addWatch(policy); err != nil {
			// Log but continue - some paths may not be accessible
			m.sendErrorEvent(fmt.Errorf("failed to watch %s: %w", policy.Path, err))
		}
	}

	// Start event loop
	m.wg.Add(1)
	go m.eventLoop(ctx)

	return nil
}

// addWatch adds a registry path to be monitored.
func (m *RegistryMonitor) addWatch(policy *RegistryPathPolicy) error {
	m.watchMu.Lock()
	defer m.watchMu.Unlock()

	if _, exists := m.watches[policy.Path]; exists {
		return nil // Already watching
	}

	// Note: Actual implementation would use RegNotifyChangeKeyValue
	// This is a stub for cross-platform compilation
	watch := &registryWatch{
		path:      policy.Path,
		policy:    policy,
		recursive: true,
	}

	m.watches[policy.Path] = watch
	return nil
}

// eventLoop processes registry change notifications.
func (m *RegistryMonitor) eventLoop(ctx context.Context) {
	defer m.wg.Done()

	// Note: Real implementation would use WaitForMultipleObjects
	// on registry notification handles. This is a stub.
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			// Polling stub - real implementation uses events
		}
	}
}

// handleRegistryChange processes a detected registry modification.
func (m *RegistryMonitor) handleRegistryChange(watch *registryWatch, operation RegistryOperation, valueName string) {
	if m.eventChan == nil {
		return
	}

	ev := types.Event{
		Timestamp: time.Now().UTC(),
		Type:      "registry_write",
		Path:      watch.path,
		Operation: string(operation),
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionAllow, // Registry monitoring is observation-only
			EffectiveDecision: types.DecisionAllow,
		},
		Fields: map[string]any{
			"source":      "registry_monitor",
			"platform":    "windows",
			"hive":        parseHive(watch.path),
			"value_name":  valueName,
			"risk_level":  watch.policy.Risk.String(),
			"description": watch.policy.Description,
			"technique":   watch.policy.Technique,
		},
	}

	m.eventChan <- ev
}

// sendErrorEvent sends an error event through the event channel.
func (m *RegistryMonitor) sendErrorEvent(err error) {
	if m.eventChan == nil {
		return
	}

	ev := types.Event{
		Timestamp: time.Now().UTC(),
		Type:      "registry_error",
		Fields: map[string]any{
			"error":    err.Error(),
			"source":   "registry_monitor",
			"platform": "windows",
		},
	}
	m.eventChan <- ev
}

// Stop stops the registry monitor.
func (m *RegistryMonitor) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	m.mu.Unlock()

	close(m.stopChan)
	m.wg.Wait()

	// Clean up watches
	m.watchMu.Lock()
	m.watches = make(map[string]*registryWatch)
	m.watchMu.Unlock()

	return nil
}

// WatchedPaths returns the list of currently watched paths.
func (m *RegistryMonitor) WatchedPaths() []string {
	m.watchMu.RLock()
	defer m.watchMu.RUnlock()

	paths := make([]string, 0, len(m.watches))
	for path := range m.watches {
		paths = append(paths, path)
	}
	return paths
}

// parseHive extracts the registry hive from a path.
func parseHive(path string) string {
	parts := strings.SplitN(path, `\`, 2)
	if len(parts) == 0 {
		return ""
	}

	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return string(HiveLocalMachine)
	case "HKCU", "HKEY_CURRENT_USER":
		return string(HiveCurrentUser)
	case "HKCR", "HKEY_CLASSES_ROOT":
		return string(HiveClassesRoot)
	case "HKU", "HKEY_USERS":
		return string(HiveUsers)
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return string(HiveCurrentConfig)
	default:
		return parts[0]
	}
}

// GetHighRiskPaths returns the list of high-risk registry paths.
func GetHighRiskPaths() []RegistryPathPolicy {
	return HighRiskRegistryPaths
}

// IsHighRiskPath checks if a path matches any high-risk pattern.
func IsHighRiskPath(path string) (bool, *RegistryPathPolicy) {
	normalizedPath := strings.ToUpper(path)
	for i := range HighRiskRegistryPaths {
		policy := &HighRiskRegistryPaths[i]
		if strings.HasPrefix(normalizedPath, strings.ToUpper(policy.Path)) {
			return true, policy
		}
	}
	return false, nil
}
