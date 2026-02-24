// internal/policygen/generator.go
package policygen

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

// Package-level compiled regexes for sanitizeName
var (
	sanitizeNameRe    = regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	sanitizeCollapseRe = regexp.MustCompile(`_+`)
)

// Generator creates policies from session events.
type Generator struct {
	store store.EventStore
}

// NewGenerator creates a new policy generator.
func NewGenerator(s store.EventStore) *Generator {
	return &Generator{store: s}
}

// Generate creates a policy from session events.
func (g *Generator) Generate(ctx context.Context, sess types.Session, opts Options) (*GeneratedPolicy, error) {
	events, err := g.store.QueryEvents(ctx, types.EventQuery{
		SessionID: sess.ID,
		Asc:       true,
	})
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("session %s has no event data; run with audit logging enabled", sess.ID)
	}

	policy := &GeneratedPolicy{
		SessionID:   sess.ID,
		GeneratedAt: time.Now().UTC(),
		EventCount:  len(events),
		Duration:    events[len(events)-1].Timestamp.Sub(events[0].Timestamp),
	}

	// Initialize detector to track risky commands
	detector := NewRiskyDetector()

	// Categorize events
	var (
		allowedFileEvents   []types.Event
		blockedFileEvents   []types.Event
		allowedNetEvents    []types.Event
		blockedNetEvents    []types.Event
		allowedCmdEvents    []types.Event
		blockedCmdEvents    []types.Event
		allowedUnixEvents   []types.Event
		blockedUnixEvents   []types.Event
		mcpEvents           []types.Event
	)

	// Track which commands made network calls or deleted files
	commandNetwork := make(map[string]bool)
	commandDestructive := make(map[string]bool)

	for _, ev := range events {
		decision := getDecision(ev)
		allowed := decision == types.DecisionAllow || decision == types.DecisionAudit

		// Track network and destructive ops by command
		if isNetworkEvent(ev.Type) && ev.CommandID != "" {
			commandNetwork[ev.CommandID] = true
		}
		if ev.Type == "file_delete" && ev.CommandID != "" {
			commandDestructive[ev.CommandID] = true
		}

		switch {
		case isFileEvent(ev.Type):
			if allowed {
				allowedFileEvents = append(allowedFileEvents, ev)
			} else if opts.IncludeBlocked {
				blockedFileEvents = append(blockedFileEvents, ev)
			}
		case isNetworkEvent(ev.Type):
			if allowed {
				allowedNetEvents = append(allowedNetEvents, ev)
			} else if opts.IncludeBlocked {
				blockedNetEvents = append(blockedNetEvents, ev)
			}
		case isCommandEvent(ev.Type):
			if allowed {
				allowedCmdEvents = append(allowedCmdEvents, ev)
			} else if opts.IncludeBlocked {
				blockedCmdEvents = append(blockedCmdEvents, ev)
			}
		case isUnixSocketEvent(ev.Type):
			if allowed {
				allowedUnixEvents = append(allowedUnixEvents, ev)
			} else if opts.IncludeBlocked {
				blockedUnixEvents = append(blockedUnixEvents, ev)
			}
		case isMCPEvent(ev.Type):
			mcpEvents = append(mcpEvents, ev)
		}
	}

	// Mark risky commands based on observed behavior
	for _, ev := range allowedCmdEvents {
		cmdID := ev.CommandID
		if cmdID == "" {
			cmdID = ev.ID
		}
		cmdName := getCommandName(ev)
		if commandNetwork[cmdID] {
			detector.MarkNetworkCapable(cmdName)
		}
		if commandDestructive[cmdID] {
			detector.MarkDestructive(cmdName)
		}
	}

	// Generate file rules
	policy.FileRules = g.generateFileRules(allowedFileEvents, opts, false)
	policy.BlockedFiles = g.generateFileRules(blockedFileEvents, opts, true)

	// Generate network rules
	policy.NetworkRules = g.generateNetworkRules(allowedNetEvents, false)
	policy.BlockedNetwork = g.generateNetworkRules(blockedNetEvents, true)

	// Generate command rules
	policy.CommandRules = g.generateCommandRules(allowedCmdEvents, detector, opts, false)
	policy.BlockedCommands = g.generateCommandRules(blockedCmdEvents, detector, opts, true)

	// Generate unix socket rules
	policy.UnixRules = g.generateUnixRules(allowedUnixEvents, false)

	// Generate MCP rules
	policy.MCPToolRules, policy.MCPBlockedTools, policy.MCPServers, policy.MCPConfig =
		g.generateMCPRules(mcpEvents, opts)

	return policy, nil
}

// generateFileRules creates file rules from events.
func (g *Generator) generateFileRules(events []types.Event, opts Options, blocked bool) []FileRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Group paths by operation
	pathsByOp := make(map[string][]string)
	eventsByPath := make(map[string][]types.Event)

	for _, ev := range events {
		op := getFileOp(ev.Type)
		if ev.Path != "" {
			pathsByOp[op] = append(pathsByOp[op], ev.Path)
			eventsByPath[ev.Path] = append(eventsByPath[ev.Path], ev)
		}
	}

	var rules []FileRuleGen

	for op, paths := range pathsByOp {
		// Deduplicate paths
		uniquePaths := uniqueStrings(paths)

		// Group paths using threshold
		groups := GroupPaths(uniquePaths, opts.Threshold)

		for _, group := range groups {
			// Build provenance
			var allEvents []types.Event
			for _, p := range group.Paths {
				allEvents = append(allEvents, eventsByPath[p]...)
			}
			prov := buildProvenance(allEvents, group.Paths, blocked, "")

			rule := FileRuleGen{
				GeneratedRule: GeneratedRule{
					Name:        sanitizeName(group.Pattern),
					Description: fmt.Sprintf("%s access to %s", op, group.Pattern),
					Provenance:  prov,
				},
				Paths:      []string{group.Pattern},
				Operations: []string{op},
				Decision:   "allow",
			}
			if blocked {
				rule.Decision = "deny"
			}
			rules = append(rules, rule)
		}
	}

	// Sort by name for deterministic output
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Name < rules[j].Name
	})

	return rules
}

// generateNetworkRules creates network rules from events.
func (g *Generator) generateNetworkRules(events []types.Event, blocked bool) []NetworkRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Collect domains
	var domains []string
	eventsByDomain := make(map[string][]types.Event)

	for _, ev := range events {
		if ev.Domain != "" {
			domains = append(domains, ev.Domain)
			eventsByDomain[ev.Domain] = append(eventsByDomain[ev.Domain], ev)
		}
	}

	// Deduplicate domains
	uniqueDomains := uniqueStrings(domains)

	// Group domains
	groups := GroupDomains(uniqueDomains)

	var rules []NetworkRuleGen
	for _, group := range groups {
		// Build provenance
		var allEvents []types.Event
		for _, d := range group.Domains {
			allEvents = append(allEvents, eventsByDomain[d]...)
		}
		prov := buildProvenance(allEvents, group.Domains, blocked, "")

		rule := NetworkRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(group.Pattern),
				Description: fmt.Sprintf("network access to %s", group.Pattern),
				Provenance:  prov,
			},
			Domains:  []string{group.Pattern},
			Ports:    group.Ports,
			Decision: "allow",
		}
		if blocked {
			rule.Decision = "deny"
		}
		rules = append(rules, rule)
	}

	// Sort by name
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Name < rules[j].Name
	})

	return rules
}

// generateCommandRules creates command rules from events.
func (g *Generator) generateCommandRules(events []types.Event, detector *RiskyDetector, opts Options, blocked bool) []CommandRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Group events by command name
	eventsByCmd := make(map[string][]types.Event)
	argsByCmd := make(map[string][][]string)

	for _, ev := range events {
		cmdName := getCommandName(ev)
		if cmdName == "" {
			continue
		}
		eventsByCmd[cmdName] = append(eventsByCmd[cmdName], ev)
		args := getCommandArgs(ev)
		if len(args) > 0 {
			argsByCmd[cmdName] = append(argsByCmd[cmdName], args)
		}
	}

	var rules []CommandRuleGen
	for cmdName, cmdEvents := range eventsByCmd {
		isRisky := detector.IsRisky(cmdName)
		reason := detector.Reason(cmdName)

		// Build provenance
		samples := []string{cmdName}
		prov := buildProvenance(cmdEvents, samples, blocked, "")

		rule := CommandRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(cmdName),
				Description: fmt.Sprintf("execute %s", cmdName),
				Provenance:  prov,
			},
			Commands: []string{cmdName},
			Decision: "allow",
			Risky:    isRisky,
		}
		if isRisky {
			rule.RiskyReason = reason
			// Generate arg pattern for risky commands if enabled
			if opts.ArgPatterns {
				if argsLists, ok := argsByCmd[cmdName]; ok && len(argsLists) > 0 {
					rule.ArgsPattern = generateArgPattern(argsLists)
				}
			}
		}
		if blocked {
			rule.Decision = "deny"
		}
		rules = append(rules, rule)
	}

	// Sort: risky commands first, then by name
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Risky != rules[j].Risky {
			return rules[i].Risky
		}
		return rules[i].Name < rules[j].Name
	})

	return rules
}

// generateUnixRules creates unix socket rules from events.
func (g *Generator) generateUnixRules(events []types.Event, blocked bool) []UnixRuleGen {
	if len(events) == 0 {
		return nil
	}

	// Group by socket path
	eventsByPath := make(map[string][]types.Event)

	for _, ev := range events {
		if ev.Path != "" {
			eventsByPath[ev.Path] = append(eventsByPath[ev.Path], ev)
		}
	}

	var rules []UnixRuleGen
	for path, pathEvents := range eventsByPath {
		prov := buildProvenance(pathEvents, []string{path}, blocked, "")

		rule := UnixRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(path),
				Description: fmt.Sprintf("unix socket access to %s", path),
				Provenance:  prov,
			},
			Paths:      []string{path},
			Operations: []string{"connect"},
			Decision:   "allow",
		}
		if blocked {
			rule.Decision = "deny"
		}
		rules = append(rules, rule)
	}

	// Sort by name
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Name < rules[j].Name
	})

	return rules
}

// getDecision extracts the effective decision from an event.
func getDecision(ev types.Event) types.Decision {
	if ev.Policy == nil {
		return types.DecisionAllow
	}
	if ev.Policy.EffectiveDecision != "" {
		return ev.Policy.EffectiveDecision
	}
	return ev.Policy.Decision
}

// isFileEvent checks if the event type is file-related.
func isFileEvent(t string) bool {
	switch t {
	case "file_read", "file_write", "file_create", "file_delete",
		"file_rename", "file_chmod", "file_chown", "file_link",
		"file_open", "file_stat":
		return true
	}
	return false
}

// isNetworkEvent checks if the event type is network-related.
func isNetworkEvent(t string) bool {
	switch t {
	case "net_connect", "net_listen", "net_accept", "net_send", "net_recv",
		"dns_query", "dns_resolve":
		return true
	}
	return false
}

// isCommandEvent checks if the event type is command-related.
func isCommandEvent(t string) bool {
	switch t {
	case "command_started", "command_finished", "command_policy",
		"exec", "exec_start", "exec_end", "command", "spawn":
		return true
	}
	return false
}

// isUnixSocketEvent checks if the event type is unix socket-related.
func isUnixSocketEvent(t string) bool {
	switch t {
	case "unix_connect", "unix_listen", "unix_accept", "unix_send", "unix_recv":
		return true
	}
	// Also check if it's abstract socket via event field
	return false
}

// isMCPEvent checks if the event type is MCP-related.
func isMCPEvent(t string) bool {
	switch t {
	case "mcp_tool_seen", "mcp_tool_changed", "mcp_tool_called",
		"mcp_tool_call_intercepted",
		"mcp_cross_server_blocked", "mcp_network_connection":
		return true
	}
	return false
}

// stringFromFields extracts a string value from event Fields.
func stringFromFields(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	if v, ok := fields[key].(string); ok {
		return v
	}
	return ""
}

// getFileOp converts event type to operation string.
func getFileOp(t string) string {
	switch t {
	case "file_read", "file_open", "file_stat":
		return "read"
	case "file_write":
		return "write"
	case "file_create":
		return "create"
	case "file_delete":
		return "delete"
	case "file_rename":
		return "rename"
	case "file_chmod", "file_chown":
		return "modify"
	case "file_link":
		return "link"
	default:
		return "access"
	}
}

// getCommandName extracts the command name from an event.
func getCommandName(ev types.Event) string {
	// Try fields first
	if ev.Fields != nil {
		if cmd, ok := ev.Fields["command"].(string); ok && cmd != "" {
			return filepath.Base(cmd)
		}
		if exe, ok := ev.Fields["executable"].(string); ok && exe != "" {
			return filepath.Base(exe)
		}
		if argv, ok := ev.Fields["argv"].([]interface{}); ok && len(argv) > 0 {
			if arg0, ok := argv[0].(string); ok && arg0 != "" {
				return filepath.Base(arg0)
			}
		}
	}
	// Fall back to path field
	if ev.Path != "" {
		return filepath.Base(ev.Path)
	}
	return ""
}

// getCommandArgs extracts command arguments from an event.
func getCommandArgs(ev types.Event) []string {
	if ev.Fields == nil {
		return nil
	}

	// Try argv field
	if argv, ok := ev.Fields["argv"].([]interface{}); ok && len(argv) > 1 {
		args := make([]string, 0, len(argv)-1)
		for i := 1; i < len(argv); i++ {
			if arg, ok := argv[i].(string); ok {
				args = append(args, arg)
			}
		}
		return args
	}

	// Try args field
	if args, ok := ev.Fields["args"].([]interface{}); ok {
		result := make([]string, 0, len(args))
		for _, arg := range args {
			if s, ok := arg.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// sanitizeName converts a path/domain to a valid rule name.
func sanitizeName(s string) string {
	// Replace special chars with underscores
	name := sanitizeNameRe.ReplaceAllString(s, "_")

	// Remove leading/trailing underscores
	name = strings.Trim(name, "_")

	// Collapse multiple underscores
	name = sanitizeCollapseRe.ReplaceAllString(name, "_")

	// Limit length
	if len(name) > 50 {
		name = name[:50]
	}

	if name == "" {
		name = "rule"
	}

	return name
}

// generateArgPattern creates a regex pattern from observed argument lists.
func generateArgPattern(argsLists [][]string) string {
	if len(argsLists) == 0 {
		return ""
	}

	// Find common prefixes in arguments
	// For simplicity, just quote the observed args as a pattern
	var patterns []string
	seen := make(map[string]bool)

	for _, args := range argsLists {
		argStr := strings.Join(args, " ")
		if !seen[argStr] {
			seen[argStr] = true
			// Escape special regex chars
			escaped := regexp.QuoteMeta(argStr)
			patterns = append(patterns, escaped)
		}
	}

	if len(patterns) == 0 {
		return ""
	}

	if len(patterns) == 1 {
		return "^" + patterns[0] + "$"
	}

	// Create alternation pattern
	return "^(" + strings.Join(patterns, "|") + ")$"
}

// buildProvenance creates provenance from events.
func buildProvenance(events []types.Event, samples []string, blocked bool, reason string) Provenance {
	prov := Provenance{
		EventCount:  len(events),
		Blocked:     blocked,
		BlockReason: reason,
	}

	if len(events) > 0 {
		prov.FirstSeen = events[0].Timestamp
		prov.LastSeen = events[len(events)-1].Timestamp
	}

	// Take up to 3 samples
	if len(samples) > 3 {
		prov.SamplePaths = samples[:3]
	} else {
		prov.SamplePaths = samples
	}

	return prov
}

// uniqueStrings returns unique strings preserving order.
func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// generateMCPRules creates MCP policy rules from events.
func (g *Generator) generateMCPRules(events []types.Event, opts Options) (
	toolRules []MCPToolRuleGen,
	blockedTools []MCPToolRuleGen,
	servers []MCPServerRuleGen,
	config *MCPPolicyConfig,
) {
	if len(events) == 0 {
		return nil, nil, nil, nil
	}

	// Track tools by server+tool identity
	type toolKey struct {
		serverID string
		toolName string
	}
	type toolInfo struct {
		serverID    string
		toolName    string
		contentHash string
		blockReason string
		events      []types.Event
	}
	seenTools := make(map[toolKey]*toolInfo)
	blockedToolMap := make(map[toolKey]*toolInfo)
	serverTools := make(map[string]map[string]bool) // server_id -> set of tool names

	var hasChangedTools bool
	var crossServerRules []string
	crossServerRuleSet := make(map[string]bool)

	for _, ev := range events {
		serverID := stringFromFields(ev.Fields, "server_id")

		switch ev.Type {
		case "mcp_tool_seen":
			toolName := stringFromFields(ev.Fields, "tool_name")
			hash := stringFromFields(ev.Fields, "tool_hash")
			if serverID != "" && toolName != "" {
				key := toolKey{serverID, toolName}
				if _, ok := seenTools[key]; !ok {
					seenTools[key] = &toolInfo{
						serverID:    serverID,
						toolName:    toolName,
						contentHash: hash,
					}
				}
				seenTools[key].events = append(seenTools[key].events, ev)

				if serverTools[serverID] == nil {
					serverTools[serverID] = make(map[string]bool)
				}
				serverTools[serverID][toolName] = true
			}

		case "mcp_tool_called", "mcp_tool_call_intercepted":
			toolName := stringFromFields(ev.Fields, "tool_name")
			action := stringFromFields(ev.Fields, "action")

			if ev.Type == "mcp_tool_call_intercepted" && action == "block" {
				if serverID != "" && toolName != "" {
					key := toolKey{serverID, toolName}
					if _, ok := blockedToolMap[key]; !ok {
						blockedToolMap[key] = &toolInfo{
							serverID: serverID,
							toolName: toolName,
						}
					}
					info := blockedToolMap[key]
					info.events = append(info.events, ev)
					// Capture first block reason
					if reason := stringFromFields(ev.Fields, "reason"); reason != "" && info.blockReason == "" {
						info.blockReason = reason
					}
				}
			}

			// Track server activity
			if serverID != "" {
				if serverTools[serverID] == nil {
					serverTools[serverID] = make(map[string]bool)
				}
				if toolName != "" {
					serverTools[serverID][toolName] = true
				}
			}

		case "mcp_tool_changed":
			hasChangedTools = true

		case "mcp_cross_server_blocked":
			rule := stringFromFields(ev.Fields, "rule")
			if rule != "" && !crossServerRuleSet[rule] {
				crossServerRuleSet[rule] = true
				crossServerRules = append(crossServerRules, rule)
			}

		case "mcp_network_connection":
			if serverID != "" {
				if serverTools[serverID] == nil {
					serverTools[serverID] = make(map[string]bool)
				}
			}
		}
	}

	// Build tool rules from seen tools
	for _, info := range seenTools {
		prov := buildProvenance(info.events, []string{info.serverID + "/" + info.toolName}, false, "")
		toolRules = append(toolRules, MCPToolRuleGen{
			GeneratedRule: GeneratedRule{
				Name:        sanitizeName(info.serverID + "-" + info.toolName),
				Description: fmt.Sprintf("MCP tool %s/%s", info.serverID, info.toolName),
				Provenance:  prov,
			},
			ServerID:    info.serverID,
			ToolName:    info.toolName,
			ContentHash: info.contentHash,
		})
	}

	// Build blocked tool rules
	if opts.IncludeBlocked {
		for _, info := range blockedToolMap {
			reason := info.blockReason
			prov := buildProvenance(info.events, []string{info.serverID + "/" + info.toolName}, true, reason)
			blockedTools = append(blockedTools, MCPToolRuleGen{
				GeneratedRule: GeneratedRule{
					Name:        sanitizeName(info.serverID + "-" + info.toolName),
					Description: fmt.Sprintf("MCP tool %s/%s (blocked)", info.serverID, info.toolName),
					Provenance:  prov,
				},
				ServerID:    info.serverID,
				ToolName:    info.toolName,
				Blocked:     true,
				BlockReason: reason,
			})
		}
	}

	// Build server list
	for serverID, tools := range serverTools {
		servers = append(servers, MCPServerRuleGen{
			ServerID:  serverID,
			ToolCount: len(tools),
		})
	}

	// Sort for deterministic output
	sort.Slice(toolRules, func(i, j int) bool { return toolRules[i].Name < toolRules[j].Name })
	sort.Slice(blockedTools, func(i, j int) bool { return blockedTools[i].Name < blockedTools[j].Name })
	sort.Slice(servers, func(i, j int) bool { return servers[i].ServerID < servers[j].ServerID })

	// Build MCP config
	config = &MCPPolicyConfig{
		VersionPinning:   hasChangedTools,
		VersionOnChange:  "block",
		CrossServer:      len(crossServerRules) > 0,
		CrossServerRules: crossServerRules,
	}
	// Always recommend version pinning if tools have hashes
	for _, r := range toolRules {
		if r.ContentHash != "" {
			config.VersionPinning = true
			break
		}
	}

	return toolRules, blockedTools, servers, config
}
