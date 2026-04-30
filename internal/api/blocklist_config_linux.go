//go:build linux && cgo

package api

import (
	"log/slog"
	"runtime"

	"github.com/agentsh/agentsh/internal/config"
	unixmon "github.com/agentsh/agentsh/internal/netmonitor/unix"
	seccompkg "github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

// buildBlockListConfigFor returns the per-session *BlockListConfig derived
// from Sandbox.Seccomp.Syscalls and Sandbox.Seccomp.BlockedSocketFamilies.
// When on_block is errno or kill the seccomp filter handles the action
// kernel-side and no notify traps fire — an empty config is returned in that
// case (nil-safe; IsBlockListed returns (_, false)).
// Socket-family entries with log/log_and_kill actions are always included in
// FamilyByKey regardless of the syscall on_block setting.
//
// Returns a non-nil *BlockListConfig (wrapped as any so the signature matches
// the non-Linux stub) so callers can always probe len(ActionByNr) without a
// separate nil check.
func (a *App) buildBlockListConfigFor(sessionID string) any {
	cfg := &unixmon.BlockListConfig{}

	// Syscall block-list: only log/log_and_kill route through notify.
	action, ok := seccompkg.ParseOnBlock(a.cfg.Sandbox.Seccomp.Syscalls.OnBlock)
	if ok && (action == seccompkg.OnBlockLog || action == seccompkg.OnBlockLogAndKill) {
		nrs, skipped := seccompkg.ResolveSyscalls(a.cfg.Sandbox.Seccomp.Syscalls.Block)
		if len(skipped) > 0 {
			slog.Warn("blocklist: some syscalls could not be resolved on this arch",
				"session_id", sessionID, "skipped", skipped, "arch", runtime.GOARCH)
		}
		cfg.ActionByNr = make(map[uint32]seccompkg.OnBlockAction, len(nrs))
		for _, nr := range nrs {
			cfg.ActionByNr[uint32(nr)] = action
		}
	}

	// Socket-family block-list: log/log_and_kill families route through notify.
	// Build (syscallNr<<32)|af_family → BlockedFamily for dispatch in the handler.
	if len(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies) > 0 {
		families, err := config.ResolveBlockedFamilies(a.cfg.Sandbox.Seccomp.BlockedSocketFamilies)
		if err != nil {
			slog.Warn("blocklist: failed to resolve blocked_socket_families for notify dispatch",
				"session_id", sessionID, "error", err)
		} else {
			for _, bf := range families {
				if bf.Action != seccompkg.OnBlockLog && bf.Action != seccompkg.OnBlockLogAndKill {
					continue
				}
				if cfg.FamilyByKey == nil {
					cfg.FamilyByKey = make(map[uint64]seccompkg.BlockedFamily)
				}
				cfg.FamilyByKey[uint64(unix.SYS_SOCKET)<<32|uint64(bf.Family)] = bf
				cfg.FamilyByKey[uint64(unix.SYS_SOCKETPAIR)<<32|uint64(bf.Family)] = bf
			}
		}
	}

	return cfg
}
