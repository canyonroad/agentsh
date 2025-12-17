package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	grpcServiceName           = "agentsh.v1.Agentsh"
	grpcMethodCreateSession   = "/agentsh.v1.Agentsh/CreateSession"
	grpcMethodExec            = "/agentsh.v1.Agentsh/Exec"
	defaultGRPCAPIKeyMetadata = "x-api-key"
)

type grpcServer struct {
	app *App
}

type AgentshGRPCServer interface {
	CreateSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	Exec(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

func RegisterGRPC(s *grpc.Server, app *App) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: grpcServiceName,
		HandlerType: (*AgentshGRPCServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "CreateSession",
				Handler:    grpcHandleCreateSession,
			},
			{
				MethodName: "Exec",
				Handler:    grpcHandleExec,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "proto/agentsh/v1/agentsh.proto",
	}, &grpcServer{app: app})
}

func grpcHandleCreateSession(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	base := func(ctx context.Context, req any) (any, error) {
		return srv.(*grpcServer).CreateSession(ctx, req.(*structpb.Struct))
	}
	if interceptor == nil {
		return base(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: grpcMethodCreateSession}
	return interceptor(ctx, in, info, base)
}

func grpcHandleExec(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := &structpb.Struct{}
	if err := dec(in); err != nil {
		return nil, err
	}
	base := func(ctx context.Context, req any) (any, error) {
		return srv.(*grpcServer).Exec(ctx, req.(*structpb.Struct))
	}
	if interceptor == nil {
		return base(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: grpcMethodExec}
	return interceptor(ctx, in, info, base)
}

func (s *grpcServer) CreateSession(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	b, _ := json.Marshal(reqMap)
	return s.app.grpcCreateSession(ctx, b)
}

func (s *grpcServer) Exec(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	b, _ := json.Marshal(reqMap)
	return s.app.grpcExec(ctx, b)
}

func mustProtoJSON(in *structpb.Struct) []byte {
	b, _ := protojson.Marshal(in)
	return b
}

func GRPCUnaryAuthInterceptor(app *App) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := grpcAuth(app, ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func GRPCStreamAuthInterceptor(app *App) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := grpcAuth(app, ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func grpcAuth(app *App, ctx context.Context) error {
	if app == nil || app.cfg == nil {
		return status.Error(codes.Internal, "server not initialized")
	}
	if app.cfg.Development.DisableAuth || strings.EqualFold(app.cfg.Auth.Type, "none") {
		return nil
	}
	if !strings.EqualFold(app.cfg.Auth.Type, "api_key") {
		return status.Error(codes.Unauthenticated, "unsupported auth type")
	}
	if app.apiKeyAuth == nil {
		return status.Error(codes.Unavailable, "api key auth enabled but keys not loaded")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}

	headerName := strings.ToLower(strings.TrimSpace(app.apiKeyAuth.HeaderName()))
	key := firstMetadataValue(md, headerName)
	if key == "" && headerName != defaultGRPCAPIKeyMetadata {
		key = firstMetadataValue(md, defaultGRPCAPIKeyMetadata)
	}
	if key == "" || !app.apiKeyAuth.IsAllowed(key) {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	return nil
}

func firstMetadataValue(md metadata.MD, key string) string {
	if key == "" {
		return ""
	}
	vals := md.Get(strings.ToLower(key))
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (a *App) grpcCreateSession(ctx context.Context, reqJSON []byte) (*structpb.Struct, error) {
	var req CreateSessionRequestCompat
	if err := json.Unmarshal(reqJSON, &req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	sess, httpCode, err := a.createSessionCore(ctx, req.ToTypes())
	if err != nil {
		return nil, status.Error(codeFromHTTP(httpCode), err.Error())
	}
	out := &structpb.Struct{}
	b, _ := json.Marshal(sess)
	if err := protojson.Unmarshal(b, out); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("marshal response: %v", err))
	}
	return out, nil
}

func (a *App) grpcExec(ctx context.Context, reqJSON []byte) (*structpb.Struct, error) {
	var req execRequestCompat
	if err := json.Unmarshal(reqJSON, &req); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	resp, httpCode, err := a.execInSessionCore(ctx, req.SessionID, req.ToTypes())
	if err != nil {
		return nil, status.Error(codeFromHTTP(httpCode), err.Error())
	}
	if resp == nil {
		return nil, status.Error(codes.Internal, "empty response")
	}
	out := &structpb.Struct{}
	b, _ := json.Marshal(resp)
	if err := protojson.Unmarshal(b, out); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("marshal response: %v", err))
	}
	return out, nil
}

func codeFromHTTP(code int) codes.Code {
	switch code {
	case 400:
		return codes.InvalidArgument
	case 401:
		return codes.Unauthenticated
	case 403:
		return codes.PermissionDenied
	case 404:
		return codes.NotFound
	case 409:
		return codes.AlreadyExists
	default:
		return codes.Internal
	}
}

// CreateSessionRequestCompat matches the HTTP create session JSON.
type CreateSessionRequestCompat struct {
	ID       string `json:"id"`
	Workspace string `json:"workspace"`
	Policy   string `json:"policy"`
}

func (c CreateSessionRequestCompat) ToTypes() types.CreateSessionRequest {
	return types.CreateSessionRequest{ID: c.ID, Workspace: c.Workspace, Policy: c.Policy}
}

// execRequestCompat matches HTTP ExecRequest plus a session_id field.
type execRequestCompat struct {
	SessionID     string            `json:"session_id"`
	Command       string            `json:"command"`
	Args          []string          `json:"args"`
	WorkingDir    string            `json:"working_dir"`
	Timeout       string            `json:"timeout"`
	Stdin         string            `json:"stdin"`
	Env           map[string]string `json:"env"`
	IncludeEvents string            `json:"include_events"`
}

func (e execRequestCompat) ToTypes() types.ExecRequest {
	return types.ExecRequest{
		Command:       e.Command,
		Args:          e.Args,
		WorkingDir:    e.WorkingDir,
		Timeout:       e.Timeout,
		Stdin:         e.Stdin,
		Env:           e.Env,
		IncludeEvents: e.IncludeEvents,
	}
}
