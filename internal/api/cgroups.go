package api

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/limits"
	"github.com/agentsh/agentsh/internal/metrics"
	ebpftrace "github.com/agentsh/agentsh/internal/netmonitor/ebpf"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

func applyCgroupV2(ctx context.Context, emit storeEmitter, cfg *config.Config, sessionID, cmdID string, pid int, lim policy.Limits, m *metrics.Collector) (func() error, error) {
	if cfg == nil || !cfg.Sandbox.Cgroups.Enabled {
		return nil, nil
	}

	ebpfEnabled := cfg.Sandbox.Network.EBPF.Enabled
	ebpfRequired := cfg.Sandbox.Network.EBPF.Required

	parent := strings.TrimSpace(cfg.Sandbox.Cgroups.BasePath)
	if parent != "" && !filepath.IsAbs(parent) {
		if cur, err := limits.CurrentCgroupDir(); err == nil {
			parent = filepath.Join(cur, parent)
		}
	}

	memBytes := int64(0)
	if lim.MaxMemoryMB > 0 {
		memBytes = int64(lim.MaxMemoryMB) * 1024 * 1024
	}
	cg, err := limits.ApplyCgroupV2(parent, "agentsh-"+sanitizeCgroupTag(sessionID)+"-"+sanitizeCgroupTag(cmdID), pid, limits.CgroupV2Limits{
		MaxMemoryBytes: memBytes,
		CPUQuotaPct:    lim.CPUQuotaPercent,
		PidsMax:        lim.PidsMax,
	})
	if err != nil {
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

	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "cgroup_applied",
		SessionID: sessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"path":           cg.Path,
			"max_memory_mb":  lim.MaxMemoryMB,
			"cpu_quota_pct":  lim.CPUQuotaPercent,
			"pids_max":       lim.PidsMax,
			"base_path_used": parent,
		},
	}
	_ = emit.AppendEvent(ctx, ev)
	emit.Publish(ev)

	var ebpfDetach func() error
	var ebpfCollector *ebpftrace.Collector
	if ebpfEnabled {
		status := ebpftrace.CheckSupport()
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
				return nil, fmt.Errorf("ebpf required but unsupported: %s", status.Reason)
			}
		} else {
			if coll, detach, err := ebpftrace.AttachConnectToCgroup(cg.Path); err != nil {
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
					return nil, fmt.Errorf("ebpf attach failed and required: %w", err)
				}
			} else {
				ebpfDetach = detach
				collector, cerr := ebpftrace.StartCollector(coll, 4096)
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
						return nil, fmt.Errorf("ebpf collector failed and required: %w", cerr)
					}
					_ = detach()
				} else {
					collector.SetOnDrop(func() {
						if m != nil {
							m.IncEBPFDropped()
						}
					})
					ebpfCollector = collector
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

	return func() error {
		if ebpfCollector != nil {
			_ = ebpfCollector.Close()
		}
		if ebpfDetach != nil {
			_ = ebpfDetach()
		}
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
	}, nil
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
