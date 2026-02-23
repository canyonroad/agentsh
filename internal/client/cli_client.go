package client

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type CLIClient interface {
	CreateSession(ctx context.Context, workspace, policy string) (types.Session, error)
	CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error)
	CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error)
	ListSessions(ctx context.Context) ([]types.Session, error)
	GetSession(ctx context.Context, id string) (types.Session, error)
	DestroySession(ctx context.Context, id string) error
	PatchSession(ctx context.Context, id string, req types.SessionPatchRequest) (types.Session, error)

	Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error)
	ExecStream(ctx context.Context, sessionID string, req types.ExecRequest) (io.ReadCloser, error)
	KillCommand(ctx context.Context, sessionID string, commandID string) error

	QuerySessionEvents(ctx context.Context, sessionID string, q url.Values) ([]types.Event, error)
	SearchEvents(ctx context.Context, q url.Values) ([]types.Event, error)
	StreamSessionEvents(ctx context.Context, sessionID string) (io.ReadCloser, error)

	OutputChunk(ctx context.Context, sessionID, commandID string, stream string, offset, limit int64) (map[string]any, error)

	ListApprovals(ctx context.Context) ([]map[string]any, error)
	ResolveApproval(ctx context.Context, id string, decision string, reason string) error

	PolicyTest(ctx context.Context, sessionID, operation, path string) (map[string]any, error)
	GetProxyStatus(ctx context.Context, sessionID string) (map[string]any, error)

	// Taint-related operations
	ListTaints(ctx context.Context, sessionID string) ([]types.TaintInfo, error)
	GetTaint(ctx context.Context, pid int) (*types.TaintInfo, error)
	GetTaintTrace(ctx context.Context, pid int) (*types.TaintTrace, error)
	WatchTaints(ctx context.Context, agentOnly bool, handler func(types.TaintEvent)) error

	// Wrap-related operations
	WrapInit(ctx context.Context, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, error)

	// MCP-related operations
	ListMCPTools(ctx context.Context, q url.Values) ([]map[string]any, error)
	ListMCPServers(ctx context.Context) ([]map[string]any, error)
}

type CLIOptions struct {
	HTTPBaseURL   string
	GRPCAddr      string
	APIKey        string
	Transport     string        // http|grpc
	ClientTimeout time.Duration // HTTP client timeout (0 = default 30s)
}

func NewForCLI(opts CLIOptions) (CLIClient, error) {
	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" {
		transport = "http"
	}
	switch transport {
	case "http":
		return NewWithTimeout(opts.HTTPBaseURL, opts.APIKey, opts.ClientTimeout), nil
	case "grpc":
		httpc := NewWithTimeout(opts.HTTPBaseURL, opts.APIKey, opts.ClientTimeout)
		gaddr := strings.TrimSpace(opts.GRPCAddr)
		if gaddr == "" {
			gaddr = "127.0.0.1:9090"
		}
		grpcC, err := NewGRPC(gaddr, opts.APIKey)
		if err != nil {
			return nil, err
		}
		return &HybridClient{Client: httpc, grpc: grpcC}, nil
	default:
		return nil, fmt.Errorf("unknown transport %q (expected http|grpc)", opts.Transport)
	}
}

type HybridClient struct {
	*Client
	grpc *GRPCClient
}

func (h *HybridClient) CreateSession(ctx context.Context, workspace, policy string) (types.Session, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.CreateSession(ctx, workspace, policy)
	}
	return h.Client.CreateSession(ctx, workspace, policy)
}

func (h *HybridClient) CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.CreateSessionWithID(ctx, id, workspace, policy)
	}
	return h.Client.CreateSessionWithID(ctx, id, workspace, policy)
}

func (h *HybridClient) CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.CreateSessionWithRequest(ctx, req)
	}
	return h.Client.CreateSessionWithRequest(ctx, req)
}

func (h *HybridClient) Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.Exec(ctx, sessionID, req)
	}
	return h.Client.Exec(ctx, sessionID, req)
}

func (h *HybridClient) ExecStream(ctx context.Context, sessionID string, req types.ExecRequest) (io.ReadCloser, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.ExecStream(ctx, sessionID, req)
	}
	return h.Client.ExecStream(ctx, sessionID, req)
}

func (h *HybridClient) StreamSessionEvents(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.StreamSessionEvents(ctx, sessionID)
	}
	return h.Client.StreamSessionEvents(ctx, sessionID)
}

// ListSessions returns all sessions. Uses gRPC if available.
func (h *HybridClient) ListSessions(ctx context.Context) ([]types.Session, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.ListSessions(ctx)
	}
	return h.Client.ListSessions(ctx)
}

// GetSession returns a session by ID. Uses gRPC if available.
func (h *HybridClient) GetSession(ctx context.Context, id string) (types.Session, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.GetSession(ctx, id)
	}
	return h.Client.GetSession(ctx, id)
}

// DestroySession destroys a session. Uses gRPC if available.
func (h *HybridClient) DestroySession(ctx context.Context, id string) error {
	if h != nil && h.grpc != nil {
		return h.grpc.DestroySession(ctx, id)
	}
	return h.Client.DestroySession(ctx, id)
}

// PatchSession patches a session. Uses gRPC if available.
func (h *HybridClient) PatchSession(ctx context.Context, id string, req types.SessionPatchRequest) (types.Session, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.PatchSession(ctx, id, req)
	}
	return h.Client.PatchSession(ctx, id, req)
}

// KillCommand kills a running command. Uses gRPC if available.
func (h *HybridClient) KillCommand(ctx context.Context, sessionID, commandID string) error {
	if h != nil && h.grpc != nil {
		return h.grpc.KillCommand(ctx, sessionID, commandID)
	}
	return h.Client.KillCommand(ctx, sessionID, commandID)
}

// QuerySessionEvents queries events for a session. Uses gRPC if available.
func (h *HybridClient) QuerySessionEvents(ctx context.Context, sessionID string, q url.Values) ([]types.Event, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.QuerySessionEvents(ctx, sessionID, q)
	}
	return h.Client.QuerySessionEvents(ctx, sessionID, q)
}

// SearchEvents searches events across sessions. Uses gRPC if available.
func (h *HybridClient) SearchEvents(ctx context.Context, q url.Values) ([]types.Event, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.SearchEvents(ctx, q)
	}
	return h.Client.SearchEvents(ctx, q)
}

// OutputChunk retrieves output chunks. Uses gRPC if available.
func (h *HybridClient) OutputChunk(ctx context.Context, sessionID, commandID, stream string, offset, limit int64) (map[string]any, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.OutputChunk(ctx, sessionID, commandID, stream, offset, limit)
	}
	return h.Client.OutputChunk(ctx, sessionID, commandID, stream, offset, limit)
}

// ListApprovals lists pending approvals. Uses gRPC if available.
func (h *HybridClient) ListApprovals(ctx context.Context) ([]map[string]any, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.ListApprovals(ctx)
	}
	return h.Client.ListApprovals(ctx)
}

// ResolveApproval resolves an approval. Uses gRPC if available.
func (h *HybridClient) ResolveApproval(ctx context.Context, id, decision, reason string) error {
	if h != nil && h.grpc != nil {
		return h.grpc.ResolveApproval(ctx, id, decision, reason)
	}
	return h.Client.ResolveApproval(ctx, id, decision, reason)
}

// PolicyTest tests policy. Uses gRPC if available.
func (h *HybridClient) PolicyTest(ctx context.Context, sessionID, operation, path string) (map[string]any, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.PolicyTest(ctx, sessionID, operation, path)
	}
	return h.Client.PolicyTest(ctx, sessionID, operation, path)
}

// GetProxyStatus gets the proxy status for a session. Uses gRPC if available.
func (h *HybridClient) GetProxyStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	if h != nil && h.grpc != nil {
		return h.grpc.GetProxyStatus(ctx, sessionID)
	}
	return h.Client.GetProxyStatus(ctx, sessionID)
}

// ListTaints lists all tainted processes.
func (h *HybridClient) ListTaints(ctx context.Context, sessionID string) ([]types.TaintInfo, error) {
	return h.Client.ListTaints(ctx, sessionID)
}

// GetTaint gets taint info for a specific PID.
func (h *HybridClient) GetTaint(ctx context.Context, pid int) (*types.TaintInfo, error) {
	return h.Client.GetTaint(ctx, pid)
}

// GetTaintTrace gets the full ancestry trace for a PID.
func (h *HybridClient) GetTaintTrace(ctx context.Context, pid int) (*types.TaintTrace, error) {
	return h.Client.GetTaintTrace(ctx, pid)
}

// WatchTaints watches for taint events.
func (h *HybridClient) WatchTaints(ctx context.Context, agentOnly bool, handler func(types.TaintEvent)) error {
	return h.Client.WatchTaints(ctx, agentOnly, handler)
}

// WrapInit initializes seccomp wrapping for a session.
func (h *HybridClient) WrapInit(ctx context.Context, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, error) {
	return h.Client.WrapInit(ctx, sessionID, req)
}

// ListMCPTools lists MCP tools matching the given query parameters.
func (h *HybridClient) ListMCPTools(ctx context.Context, q url.Values) ([]map[string]any, error) {
	return h.Client.ListMCPTools(ctx, q)
}

// ListMCPServers lists MCP server summaries.
func (h *HybridClient) ListMCPServers(ctx context.Context) ([]map[string]any, error) {
	return h.Client.ListMCPServers(ctx)
}
