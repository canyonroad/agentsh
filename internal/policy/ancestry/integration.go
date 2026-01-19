package ancestry

import (
	"github.com/agentsh/agentsh/internal/process"
)

// ProcessTreeIntegration bridges ProcessTree events to TaintCache.
type ProcessTreeIntegration struct {
	tree  *process.ProcessTree
	cache *TaintCache

	// infoProvider is called to get detailed process info when spawn is detected.
	// If nil, minimal info (PID/PPID only) will be used.
	infoProvider func(pid int) (*ProcessInfo, error)
}

// IntegrationConfig configures how ProcessTree integrates with TaintCache.
type IntegrationConfig struct {
	// InfoProvider returns detailed ProcessInfo for a PID.
	// If nil, a default provider using process.ProcessTree will be used.
	InfoProvider func(pid int) (*ProcessInfo, error)
}

// NewProcessTreeIntegration creates a bridge between ProcessTree and TaintCache.
// This connects the ProcessTree's spawn/exit events to the TaintCache.
func NewProcessTreeIntegration(tree *process.ProcessTree, cache *TaintCache, cfg *IntegrationConfig) *ProcessTreeIntegration {
	pti := &ProcessTreeIntegration{
		tree:  tree,
		cache: cache,
	}

	if cfg != nil && cfg.InfoProvider != nil {
		pti.infoProvider = cfg.InfoProvider
	}

	// Wire up callbacks
	tree.OnSpawn(func(node *process.ProcessNode) {
		pti.handleSpawn(node)
	})

	tree.OnExit(func(node *process.ProcessNode, exitCode int) {
		pti.handleExit(node)
	})

	return pti
}

func (pti *ProcessTreeIntegration) handleSpawn(node *process.ProcessNode) {
	if node == nil {
		return
	}

	// Build ProcessInfo
	info := &ProcessInfo{
		PID:  node.PID,
		PPID: node.PPID,
		Comm: node.Command,
	}

	// Try to get enriched info if provider is available
	if pti.infoProvider != nil {
		if enriched, err := pti.infoProvider(node.PID); err == nil && enriched != nil {
			// Preserve PID/PPID from node (more reliable)
			enriched.PID = node.PID
			enriched.PPID = node.PPID
			info = enriched
		}
	}

	// If command is still empty, use node.Command
	if info.Comm == "" && node.Command != "" {
		info.Comm = node.Command
	}

	// If we have args from node but not cmdline
	if len(info.Cmdline) == 0 && len(node.Args) > 0 {
		info.Cmdline = append([]string{node.Command}, node.Args...)
	}

	pti.cache.OnSpawn(node.PID, node.PPID, info)
}

func (pti *ProcessTreeIntegration) handleExit(node *process.ProcessNode) {
	if node == nil {
		return
	}
	pti.cache.OnExit(node.PID)
}

// TaintCache returns the underlying TaintCache.
func (pti *ProcessTreeIntegration) TaintCache() *TaintCache {
	return pti.cache
}

// ProcessTree returns the underlying ProcessTree.
func (pti *ProcessTreeIntegration) ProcessTree() *process.ProcessTree {
	return pti.tree
}
