package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
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
	grpcMethodExecStream      = "/agentsh.v1.Agentsh/ExecStream"
	grpcMethodEventsTail      = "/agentsh.v1.Agentsh/EventsTail"
	defaultGRPCAPIKeyMetadata = "x-api-key"
)

type grpcServer struct {
	app *App
}

type AgentshGRPCServer interface {
	CreateSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	Exec(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ExecStream(*structpb.Struct, grpc.ServerStream) error
	EventsTail(*structpb.Struct, grpc.ServerStream) error
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
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "ExecStream",
				Handler:       grpcHandleExecStream,
				ServerStreams: true,
			},
			{
				StreamName:    "EventsTail",
				Handler:       grpcHandleEventsTail,
				ServerStreams: true,
			},
		},
		Metadata: "proto/agentsh/v1/agentsh.proto",
	}, &grpcServer{app: app})

	ptygrpc.RegisterAgentshPTYServer(s, &ptyGRPCServer{app: app})
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

func grpcHandleExecStream(srv any, stream grpc.ServerStream) error {
	in := &structpb.Struct{}
	if err := stream.RecvMsg(in); err != nil {
		return err
	}
	return srv.(*grpcServer).ExecStream(in, stream)
}

func grpcHandleEventsTail(srv any, stream grpc.ServerStream) error {
	in := &structpb.Struct{}
	if err := stream.RecvMsg(in); err != nil {
		return err
	}
	return srv.(*grpcServer).EventsTail(in, stream)
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

func (s *grpcServer) ExecStream(in *structpb.Struct, stream grpc.ServerStream) error {
	if s == nil || s.app == nil {
		return status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	b, _ := json.Marshal(reqMap)

	var req execRequestCompat
	if err := json.Unmarshal(b, &req); err != nil {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	if strings.TrimSpace(req.SessionID) == "" {
		return status.Error(codes.InvalidArgument, "session_id is required")
	}
	execReq := req.ToTypes()
	if strings.TrimSpace(execReq.Command) == "" {
		return status.Error(codes.InvalidArgument, "command is required")
	}

	sess, ok := s.app.sessions.Get(req.SessionID)
	if !ok {
		return status.Error(codes.NotFound, "session not found")
	}

	cmdID := "cmd-" + uuid.NewString()
	start := time.Now().UTC()
	unlock := sess.LockExec()
	defer unlock()
	sess.SetCurrentCommandID(cmdID)

	pre := s.app.policy.CheckCommand(execReq.Command, execReq.Args)
	redirected, originalCmd, originalArgs := applyCommandRedirect(&execReq.Command, &execReq.Args, pre)
	approvalErr := error(nil)
	if pre.PolicyDecision == types.DecisionApprove && pre.EffectiveDecision == types.DecisionApprove && s.app.approvals != nil {
		apr := approvals.Request{
			ID:        "approval-" + uuid.NewString(),
			SessionID: req.SessionID,
			CommandID: cmdID,
			Kind:      "command",
			Target:    execReq.Command,
			Rule:      pre.Rule,
			Message:   pre.Message,
			Fields: map[string]any{
				"command": execReq.Command,
				"args":    execReq.Args,
			},
		}
		res, err := s.app.approvals.RequestApproval(stream.Context(), apr)
		approvalErr = err
		if pre.Approval != nil {
			pre.Approval.ID = apr.ID
		}
		if err != nil || !res.Approved {
			pre.EffectiveDecision = types.DecisionDeny
		} else {
			pre.EffectiveDecision = types.DecisionAllow
		}
	}
	preEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_policy",
		SessionID: req.SessionID,
		CommandID: cmdID,
		Operation: "command_precheck",
		Policy: &types.PolicyInfo{
			Decision:          pre.PolicyDecision,
			EffectiveDecision: pre.EffectiveDecision,
			Rule:              pre.Rule,
			Message:           pre.Message,
			Approval:          pre.Approval,
			Redirect:          pre.Redirect,
		},
		Fields: map[string]any{
			"command": originalCmd,
			"args":    originalArgs,
		},
	}
	_ = s.app.store.AppendEvent(stream.Context(), preEv)
	s.app.broker.Publish(preEv)

	if redirected && pre.Redirect != nil {
		redirEv := types.Event{
			ID:        uuid.NewString(),
			Timestamp: start,
			Type:      "command_redirected",
			SessionID: req.SessionID,
			CommandID: cmdID,
			Policy: &types.PolicyInfo{
				Decision:          types.DecisionRedirect,
				EffectiveDecision: types.DecisionAllow,
				Rule:              pre.Rule,
				Message:           pre.Message,
				Redirect:          pre.Redirect,
			},
			Fields: map[string]any{
				"from_command": originalCmd,
				"from_args":    originalArgs,
				"to_command":   execReq.Command,
				"to_args":      execReq.Args,
			},
		}
		_ = s.app.store.AppendEvent(stream.Context(), redirEv)
		s.app.broker.Publish(redirEv)
	}

	if pre.EffectiveDecision == types.DecisionDeny {
		code := "E_POLICY_DENIED"
		if pre.PolicyDecision == types.DecisionApprove {
			code = "E_APPROVAL_DENIED"
			if approvalErr != nil && strings.Contains(strings.ToLower(approvalErr.Error()), "timeout") {
				code = "E_APPROVAL_TIMEOUT"
			}
		}
		// Match HTTP behavior: stream call fails (no partial stream).
		_ = code
		return status.Error(codes.PermissionDenied, "command denied by policy")
	}

	startEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: start,
		Type:      "command_started",
		SessionID: req.SessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"command": execReq.Command,
			"args":    execReq.Args,
		},
	}
	_ = s.app.store.AppendEvent(stream.Context(), startEv)
	s.app.broker.Publish(startEv)

	emit := func(event string, payload map[string]any) error {
		payload["event"] = event
		out := &structpb.Struct{}
		b, _ := json.Marshal(payload)
		if err := protojson.Unmarshal(b, out); err != nil {
			return status.Error(codes.Internal, "marshal stream payload")
		}
		return stream.SendMsg(out)
	}

	limits := s.app.policy.Limits()
	exitCode, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc, resources, execErr := runCommandWithResourcesStreamingEmit(
		stream.Context(),
		sess,
		cmdID,
		execReq,
		s.app.cfg,
		limits.CommandTimeout,
		emit,
		s.app.cgroupHook(req.SessionID, cmdID, limits),
	)
	_ = s.app.store.SaveOutput(stream.Context(), req.SessionID, cmdID, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)

	end := time.Now().UTC()
	endEv := types.Event{
		ID:        uuid.NewString(),
		Timestamp: end,
		Type:      "command_finished",
		SessionID: req.SessionID,
		CommandID: cmdID,
		Fields: map[string]any{
			"exit_code":      exitCode,
			"duration_ms":    int64(end.Sub(start).Milliseconds()),
			"cpu_user_ms":    resources.CPUUserMs,
			"cpu_system_ms":  resources.CPUSystemMs,
			"memory_peak_kb": resources.MemoryPeakKB,
		},
	}
	if execErr != nil {
		endEv.Fields["error"] = execErr.Error()
	}
	_ = s.app.store.AppendEvent(stream.Context(), endEv)
	s.app.broker.Publish(endEv)

	_ = emit("done", map[string]any{
		"exit_code":        exitCode,
		"duration_ms":      int64(end.Sub(start).Milliseconds()),
		"stdout_truncated": stdoutTrunc,
		"stderr_truncated": stderrTrunc,
	})

	return nil
}

func (s *grpcServer) EventsTail(in *structpb.Struct, stream grpc.ServerStream) error {
	if s == nil || s.app == nil {
		return status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return status.Error(codes.InvalidArgument, "invalid request")
	}
	sid, _ := reqMap["session_id"].(string)
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return status.Error(codes.InvalidArgument, "session_id is required")
	}
	if _, ok := s.app.sessions.Get(sid); !ok {
		return status.Error(codes.NotFound, "session not found")
	}

	ch := s.app.broker.Subscribe(sid, 200)
	defer s.app.broker.Unsubscribe(sid, ch)

	// First message mirrors HTTP's "ready" event (optional).
	ready := &structpb.Struct{}
	_ = protojson.Unmarshal([]byte(`{"event":"ready"}`), ready)
	_ = stream.SendMsg(ready)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-ch:
			out := &structpb.Struct{}
			b, _ := json.Marshal(ev)
			if err := protojson.Unmarshal(b, out); err != nil {
				return status.Error(codes.Internal, "marshal event")
			}
			if err := stream.SendMsg(out); err != nil {
				return err
			}
		}
	}
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
	ID        string `json:"id"`
	Workspace string `json:"workspace"`
	Policy    string `json:"policy"`
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
