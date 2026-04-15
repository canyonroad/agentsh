//go:build linux && cgo

package api

import (
	"log/slog"
	"runtime"

	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
)

// buildBlockListConfigFor returns the per-session *BlockListConfig derived
// from Sandbox.Seccomp.Syscalls. When on_block is errno or kill the seccomp
// filter handles the action kernel-side and no notify traps fire — an empty
// config is returned in that case (nil-safe; IsBlockListed returns (_, false)).
//
// Returns a non-nil *BlockListConfig (wrapped as any so the signature matches
// the non-Linux stub) so callers can always probe len(ActionByNr) without a
// separate nil check.
func (a *App) buildBlockListConfigFor(sessionID string) any {
	cfg := &unixmon.BlockListConfig{}
	action, ok := seccompkg.ParseOnBlock(a.cfg.Sandbox.Seccomp.Syscalls.OnBlock)
	if !ok {
		return cfg
	}
	if action != seccompkg.OnBlockLog && action != seccompkg.OnBlockLogAndKill {
		return cfg
	}
	nrs, skipped := seccompkg.ResolveSyscalls(a.cfg.Sandbox.Seccomp.Syscalls.Block)
	if len(skipped) > 0 {
		slog.Warn("blocklist: some syscalls could not be resolved on this arch",
			"session_id", sessionID, "skipped", skipped, "arch", runtime.GOARCH)
	}
	cfg.ActionByNr = make(map[uint32]seccompkg.OnBlockAction, len(nrs))
	for _, nr := range nrs {
		cfg.ActionByNr[uint32(nr)] = action
	}
	return cfg
}
