package client

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
)

type CLIClient interface {
	CreateSession(ctx context.Context, workspace, policy string) (types.Session, error)
	CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error)
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
}

type CLIOptions struct {
	HTTPBaseURL string
	GRPCAddr    string
	APIKey      string
	Transport   string // http|grpc
}

func NewForCLI(opts CLIOptions) (CLIClient, error) {
	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" {
		transport = "http"
	}
	switch transport {
	case "http":
		return New(opts.HTTPBaseURL, opts.APIKey), nil
	case "grpc":
		httpc := New(opts.HTTPBaseURL, opts.APIKey)
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
