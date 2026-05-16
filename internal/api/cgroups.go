package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/metrics"
	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

type cgroupManager interface {
	Apply(name string, pid int, lim limits.CgroupV2Limits) (*limits.CgroupV2, error)
	Probe() *limits.CgroupProbeResult
}

var (
	ebpfCheckSupport          = ebpftrace.CheckSupport
	ebpfAttachConnectToCgroup = ebpftrace.AttachConnectToCgroup
	ebpfStartCollector        = ebpftrace.StartCollector
	ebpfCgroupID              = ebpftrace.CgroupID
	ebpfPopulateAllowlist     = ebpftrace.PopulateAllowlist
	ebpfCleanupAllowlist      = ebpftrace.CleanupAllowlist
)

func applyCgroupV2(ctx context.Context, emit storeEmitter, app *App, sessionID, cmdID string, pid int, lim policy.Limits, m *metrics.Collector, pol *policy.Engine) (func() error, error) {
	cfg := app.cfg
	if cfg == nil || !cfg.Sandbox.Cgroups.Enabled {
		return nil, nil
	}

	ebpfEnabled := cfg.Sandbox.Network.EBPF.Enabled
	ebpfRequired := cfg.Sandbox.Network.EBPF.Required
	ebpfEnforce := cfg.Sandbox.Network.EBPF.Enforce
	enforceNoDNS := cfg.Sandbox.Network.EBPF.EnforceWithoutDNS

	memBytes := int64(0)
	if lim.MaxMemoryMB > 0 {
		memBytes = int64(lim.MaxMemoryMB) * 1024 * 1024
	}
	cgLimits := limits.CgroupV2Limits{
		MaxMemoryBytes: memBytes,
		CPUQuotaPct:    lim.CPUQuotaPercent,
		PidsMax:        lim.PidsMax,
	}
	needsConcreteCgroup := !cgLimits.IsEmpty() || ebpfEnabled

	if app.cgroupMgr == nil {
		if !needsConcreteCgroup {
			return func() error { return nil }, nil
		}
		return nil, &limits.CgroupUnavailableError{
			Reason: "cgroup manager not initialized",
			Limits: cgLimits,
		}
	}

	cg, err := app.cgroupMgr.Apply("agentsh-"+sanitizeCgroupTag(sessionID)+"-"+sanitizeCgroupTag(cmdID), pid, cgLimits)
	if err != nil {
		var ue *limits.CgroupUnavailableError
		if errors.As(err, &ue) {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      string(events.EventCgroupUnavailableRefusal),
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"reason":        ue.Reason,
					"max_memory_mb": lim.MaxMemoryMB,
					"cpu_quota_pct": lim.CPUQuotaPercent,
					"pids_max":      lim.PidsMax,
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			return nil, err
		}
		ev := types.Event{
			ID:        uuid.NewString(),
			Timestamp: time.Now().UTC(),
			Type:      "cgroup_apply_failed",
			SessionID: sessionID,
			CommandID: cmdID,
			Fields: map[string]any{
				"error": err.Error(),
			},
		}
		_ = emit.AppendEvent(ctx, ev)
		emit.Publish(ev)
		return nil, err
	}

	// If unavailable mode allowed us with no concrete cgroup need, treat as no-op.
	if cg == nil {
		if needsConcreteCgroup {
			return nil, &limits.CgroupUnavailableError{
				Reason: "cgroup manager returned no cgroup",
				Limits: cgLimits,
			}
		}
		return func() error { return nil }, nil
	}

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "cgroup_applied",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"path":          cg.Path,
			"mode":          string(app.cgroupMgr.Probe().Mode),
			"max_memory_mb": lim.MaxMemoryMB,
			"cpu_quota_pct": lim.CPUQuotaPercent,
			"pids_max":      lim.PidsMax,
		},
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)

	var ebpfDetach func() error
	var ebpfCollector *ebpftrace.Collector
	var allowlistColl *ebpf.Collection
	var allowCgid uint64
	var refreshCancel context.CancelFunc
	cleanupEBPFResources := func() {
		if ebpfCollector != nil {
			_ = ebpfCollector.Close()
			ebpfCollector = nil
		}
		if refreshCancel != nil {
			refreshCancel()
			refreshCancel = nil
		}
		if allowlistColl != nil && allowCgid != 0 {
			_ = ebpfCleanupAllowlist(allowlistColl, allowCgid)
			allowlistColl = nil
			allowCgid = 0
		}
		if ebpfDetach != nil {
			_ = ebpfDetach()
			ebpfDetach = nil
		}
	}
	cleanupResources := func() error {
		cleanupEBPFResources()
		cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := cg.Close(cctx); err != nil {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "cgroup_cleanup_failed",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"path":  cg.Path,
					"error": err.Error(),
				},
			}
			_ = emit.AppendEvent(context.Background(), ev)
			emit.Publish(ev)
			return err
		}
		return nil
	}
	cleanupAfterSetupFailure := func() {
		if err := cleanupResources(); err != nil {
			slog.Warn("cgroup: cleanup after setup failure failed",
				"session_id", sessionID, "command_id", cmdID, "path", cg.Path, "error", err)
		}
	}
	refreshInterval := cfg.Sandbox.Network.EBPF.DNSRefreshSeconds
	if refreshInterval <= 0 {
		refreshInterval = 0
	}
	if ebpfEnabled {
		status := ebpfCheckSupport()
		if !status.Supported {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "ebpf_unavailable",
				SessionID: sessionID,
				CommandID: cmdID,
				Fields: map[string]any{
					"reason": status.Reason,
				},
			}
			_ = emit.AppendEvent(ctx, ev)
			emit.Publish(ev)
			if m != nil {
				m.IncEBPFUnavailable()
			}
			if ebpfRequired {
				cleanupAfterSetupFailure()
				return nil, fmt.Errorf("ebpf required but unsupported: %s", status.Reason)
			}
		} else {
			if coll, detach, err := ebpfAttachConnectToCgroup(cg.Path); err != nil {
				ev := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "ebpf_attach_failed",
					SessionID: sessionID,
					CommandID: cmdID,
					Fields: map[string]any{
						"error": err.Error(),
						"path":  cg.Path,
					},
				}
				_ = emit.AppendEvent(ctx, ev)
				emit.Publish(ev)
				if m != nil {
					m.IncEBPFAttachFail()
				}
				if ebpfRequired {
					cleanupAfterSetupFailure()
					return nil, fmt.Errorf("ebpf attach failed and required: %w", err)
				}
			} else {
				ebpfDetach = detach

				// Populate allowlist before starting the collector. When eBPF is
				// required, enforcement setup failures must reject the wrap before
				// the wrapper is ACKed.
				if ebpfEnforce {
					cgid, cgErr := ebpfCgroupID(cg.Path)
					if cgErr != nil {
						ev := types.Event{
							ID:        uuid.NewString(),
							Timestamp: time.Now().UTC(),
							Type:      "ebpf_enforce_disabled",
							SessionID: sessionID,
							CommandID: cmdID,
							Fields: map[string]any{
								"error": cgErr.Error(),
							},
						}
						_ = emit.AppendEvent(ctx, ev)
						emit.Publish(ev)
						if ebpfRequired {
							cleanupAfterSetupFailure()
							return nil, fmt.Errorf("ebpf enforcement setup failed and required: cgroup id: %w", cgErr)
						}
					} else {
						allowlistColl = coll
						allowCgid = cgid
						maxTTL := time.Duration(cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds) * time.Second
						ep, cidrs, denyKeys, denyCidrs, strict, hasDomains, ttlHint := buildAllowedEndpoints(pol, maxTTL)
						if len(ep) == 0 && len(cidrs) == 0 && !enforceNoDNS {
							// disable default deny when we couldn't resolve anything
							strict = false
						}
						if err := ebpfPopulateAllowlist(coll, cgid, ep, cidrs, denyKeys, denyCidrs, strict); err != nil {
							ev := types.Event{
								ID:        uuid.NewString(),
								Timestamp: time.Now().UTC(),
								Type:      "ebpf_enforce_disabled",
								SessionID: sessionID,
								CommandID: cmdID,
								Fields: map[string]any{
									"error": err.Error(),
								},
							}
							_ = emit.AppendEvent(ctx, ev)
							emit.Publish(ev)
							if m != nil {
								m.IncEBPFAttachFail()
							}
							if ebpfRequired {
								cleanupAfterSetupFailure()
								return nil, fmt.Errorf("ebpf enforcement setup failed and required: populate allowlist: %w", err)
							}
							// best effort disable default deny and clear entries
							_ = ebpfCleanupAllowlist(coll, cgid)
							allowlistColl = nil
							allowCgid = 0
						}
						if ebpfEnforce && !strict {
							ev := types.Event{
								ID:        uuid.NewString(),
								Timestamp: time.Now().UTC(),
								Type:      "ebpf_enforce_non_strict",
								SessionID: sessionID,
								CommandID: cmdID,
								Fields: map[string]any{
									"reason": "rules include wildcards or cidrs; default-deny disabled",
								},
							}
							_ = emit.AppendEvent(ctx, ev)
							emit.Publish(ev)
						}

						// Optional DNS refresh loop for domain-based rules.
						if hasDomains && strict && refreshInterval > 0 {
							refreshCtx, cancel := context.WithCancel(ctx)
							refreshCancel = cancel
							go func() {
								base := time.Duration(refreshInterval) * time.Second
								if ttlHint > 0 && ttlHint < base {
									base = ttlHint
								}
								t := time.NewTimer(jitterInterval(base))
								defer t.Stop()
								for {
									select {
									case <-refreshCtx.Done():
										return
									case <-t.C:
										ep2, cidrs2, deny2, denyCidrs2, strict2, _, ttl2 := buildAllowedEndpoints(pol, base)
										if err := ebpfPopulateAllowlist(coll, cgid, ep2, cidrs2, deny2, denyCidrs2, strict2); err != nil {
											ev := types.Event{
												ID:        uuid.NewString(),
												Timestamp: time.Now().UTC(),
												Type:      "ebpf_enforce_refresh_failed",
												SessionID: sessionID,
												CommandID: cmdID,
												Fields: map[string]any{
													"error": err.Error(),
												},
											}
											_ = emit.AppendEvent(ctx, ev)
											emit.Publish(ev)
										}
										next := base
										if ttl2 > 0 && ttl2 < next {
											next = ttl2
										}
										t.Reset(jitterInterval(next))
									}
								}
							}()
						}
					}
				}

				collector, cerr := ebpfStartCollector(coll, 4096)
				if cerr != nil {
					ev := types.Event{
						ID:        uuid.NewString(),
						Timestamp: time.Now().UTC(),
						Type:      "ebpf_collector_failed",
						SessionID: sessionID,
						CommandID: cmdID,
						Fields: map[string]any{
							"error": cerr.Error(),
						},
					}
					_ = emit.AppendEvent(ctx, ev)
					emit.Publish(ev)
					if ebpfRequired {
						cleanupAfterSetupFailure()
						return nil, fmt.Errorf("ebpf collector failed and required: %w", cerr)
					}
					cleanupEBPFResources()
				} else {
					ebpfCollector = collector
					collector.SetOnDrop(func() {
						if m != nil {
							m.IncEBPFDropped()
						}
					})
					go forwardConnectEvents(ctx, collector.Events(), emit, sessionID, cmdID, m)
				}
				ev := types.Event{
					ID:        uuid.NewString(),
					Timestamp: time.Now().UTC(),
					Type:      "ebpf_attached",
					SessionID: sessionID,
					CommandID: cmdID,
					Fields: map[string]any{
						"path": cg.Path,
					},
				}
				_ = emit.AppendEvent(ctx, ev)
				emit.Publish(ev)
			}
		}
	}

	return cleanupResources, nil
}

func sanitizeCgroupTag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "x"
	}
	// Keep it short and path-safe.
	if len(s) > 32 {
		s = s[:32]
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r)
		case r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '_' || r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}
