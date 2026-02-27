package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/internal/policy"
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
	grpcServiceName             = "agentsh.v1.Agentsh"
	grpcMethodCreateSession     = "/agentsh.v1.Agentsh/CreateSession"
	grpcMethodListSessions      = "/agentsh.v1.Agentsh/ListSessions"
	grpcMethodGetSession        = "/agentsh.v1.Agentsh/GetSession"
	grpcMethodDestroySession    = "/agentsh.v1.Agentsh/DestroySession"
	grpcMethodPatchSession      = "/agentsh.v1.Agentsh/PatchSession"
	grpcMethodExec              = "/agentsh.v1.Agentsh/Exec"
	grpcMethodExecStream        = "/agentsh.v1.Agentsh/ExecStream"
	grpcMethodKillCommand       = "/agentsh.v1.Agentsh/KillCommand"
	grpcMethodEventsTail        = "/agentsh.v1.Agentsh/EventsTail"
	grpcMethodQueryEvents       = "/agentsh.v1.Agentsh/QueryEvents"
	grpcMethodSearchEvents      = "/agentsh.v1.Agentsh/SearchEvents"
	grpcMethodOutputChunk       = "/agentsh.v1.Agentsh/OutputChunk"
	grpcMethodListApprovals     = "/agentsh.v1.Agentsh/ListApprovals"
	grpcMethodResolveApproval   = "/agentsh.v1.Agentsh/ResolveApproval"
	grpcMethodPolicyTest        = "/agentsh.v1.Agentsh/PolicyTest"
	defaultGRPCAPIKeyMetadata   = "x-api-key"
)

type grpcServer struct {
	app *App
}

type AgentshGRPCServer interface {
	// Session management
	CreateSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ListSessions(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	DestroySession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	PatchSession(context.Context, *structpb.Struct) (*structpb.Struct, error)

	// Command execution
	Exec(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ExecStream(*structpb.Struct, grpc.ServerStream) error
	KillCommand(context.Context, *structpb.Struct) (*structpb.Struct, error)

	// Events
	EventsTail(*structpb.Struct, grpc.ServerStream) error
	QueryEvents(context.Context, *structpb.Struct) (*structpb.Struct, error)
	SearchEvents(context.Context, *structpb.Struct) (*structpb.Struct, error)

	// Output
	OutputChunk(context.Context, *structpb.Struct) (*structpb.Struct, error)

	// Approvals
	ListApprovals(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ResolveApproval(context.Context, *structpb.Struct) (*structpb.Struct, error)

	// Policy
	PolicyTest(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

func RegisterGRPC(s *grpc.Server, app *App) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: grpcServiceName,
		HandlerType: (*AgentshGRPCServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "CreateSession", Handler: grpcHandleCreateSession},
			{MethodName: "ListSessions", Handler: grpcHandleListSessions},
			{MethodName: "GetSession", Handler: grpcHandleGetSession},
			{MethodName: "DestroySession", Handler: grpcHandleDestroySession},
			{MethodName: "PatchSession", Handler: grpcHandlePatchSession},
			{MethodName: "Exec", Handler: grpcHandleExec},
			{MethodName: "KillCommand", Handler: grpcHandleKillCommand},
			{MethodName: "QueryEvents", Handler: grpcHandleQueryEvents},
			{MethodName: "SearchEvents", Handler: grpcHandleSearchEvents},
			{MethodName: "OutputChunk", Handler: grpcHandleOutputChunk},
			{MethodName: "ListApprovals", Handler: grpcHandleListApprovals},
			{MethodName: "ResolveApproval", Handler: grpcHandleResolveApproval},
			{MethodName: "PolicyTest", Handler: grpcHandlePolicyTest},
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

// grpcUnaryHandler creates a standard unary handler for a given method.
func grpcUnaryHandler(method string, fn func(*grpcServer, context.Context, *structpb.Struct) (*structpb.Struct, error)) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := &structpb.Struct{}
		if err := dec(in); err != nil {
			return nil, err
		}
		base := func(ctx context.Context, req any) (any, error) {
			return fn(srv.(*grpcServer), ctx, req.(*structpb.Struct))
		}
		if interceptor == nil {
			return base(ctx, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: method}
		return interceptor(ctx, in, info, base)
	}
}

func grpcHandleListSessions(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodListSessions, (*grpcServer).ListSessions)(srv, ctx, dec, interceptor)
}

func grpcHandleGetSession(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodGetSession, (*grpcServer).GetSession)(srv, ctx, dec, interceptor)
}

func grpcHandleDestroySession(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodDestroySession, (*grpcServer).DestroySession)(srv, ctx, dec, interceptor)
}

func grpcHandlePatchSession(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodPatchSession, (*grpcServer).PatchSession)(srv, ctx, dec, interceptor)
}

func grpcHandleKillCommand(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodKillCommand, (*grpcServer).KillCommand)(srv, ctx, dec, interceptor)
}

func grpcHandleQueryEvents(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodQueryEvents, (*grpcServer).QueryEvents)(srv, ctx, dec, interceptor)
}

func grpcHandleSearchEvents(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodSearchEvents, (*grpcServer).SearchEvents)(srv, ctx, dec, interceptor)
}

func grpcHandleOutputChunk(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodOutputChunk, (*grpcServer).OutputChunk)(srv, ctx, dec, interceptor)
}

func grpcHandleListApprovals(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodListApprovals, (*grpcServer).ListApprovals)(srv, ctx, dec, interceptor)
}

func grpcHandleResolveApproval(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodResolveApproval, (*grpcServer).ResolveApproval)(srv, ctx, dec, interceptor)
}

func grpcHandlePolicyTest(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return grpcUnaryHandler(grpcMethodPolicyTest, (*grpcServer).PolicyTest)(srv, ctx, dec, interceptor)
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

	// Propagate W3C trace context for distributed tracing correlation
	if md, ok := metadata.FromIncomingContext(stream.Context()); ok {
		if tp := firstMetadataValue(md, "traceparent"); tp != "" {
			if traceID, spanID, ok := parseTraceparent(tp); ok {
				sess.SetCurrentTraceContext(traceID, spanID)
			}
		}
	}

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
	sess.InjectTraceContext(preEv.Fields)
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
		sess.InjectTraceContext(redirEv.Fields)
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
	sess.InjectTraceContext(startEv.Fields)
	_ = s.app.store.AppendEvent(stream.Context(), startEv)
	s.app.broker.Publish(startEv)

	// Set up seccomp wrapper (Linux) for syscall enforcement
	wrapperResult := s.app.setupSeccompWrapper(execReq, req.SessionID, sess)
	wrappedReq := wrapperResult.wrappedReq
	extraCfg := wrapperResult.extraCfg

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
		wrappedReq,
		s.app.cfg,
		limits.CommandTimeout,
		emit,
		s.app.cgroupHook(req.SessionID, cmdID, limits),
		extraCfg,
	)
	_ = s.app.store.SaveOutput(stream.Context(), req.SessionID, cmdID, stdoutB, stderrB, stdoutTotal, stderrTotal, stdoutTrunc, stderrTrunc)

	// Check if process was killed by seccomp (SIGSYS) and emit event
	emitSeccompBlockedIfSIGSYS(stream.Context(), s.app.store, s.app.broker, req.SessionID, cmdID, execErr)

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
	sess.InjectTraceContext(endEv.Fields)
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

func (s *grpcServer) ListSessions(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	all := s.app.sessions.List()
	out := make([]types.Session, 0, len(all))
	for _, sess := range all {
		out = append(out, sess.Snapshot())
	}
	return jsonToProto(out)
}

func (s *grpcServer) GetSession(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	id, _ := reqMap["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	sess, ok := s.app.sessions.Get(id)
	if !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	return jsonToProto(sess.Snapshot())
}

func (s *grpcServer) DestroySession(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	id, _ := reqMap["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	sess, ok := s.app.sessions.Get(id)
	if !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	_ = sess.CloseNetNS()
	_ = sess.CloseProxy()
	_ = sess.UnmountWorkspace()
	s.app.purgeTrashForSession(sess)
	_ = s.app.sessions.Destroy(id)
	return jsonToProto(map[string]any{"ok": true})
}

func (s *grpcServer) PatchSession(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	id, _ := reqMap["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	sess, ok := s.app.sessions.Get(id)
	if !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}

	// Parse patch request fields
	var req types.SessionPatchRequest
	if cwd, ok := reqMap["cwd"].(string); ok {
		req.Cwd = cwd
	}
	if env, ok := reqMap["env"].(map[string]any); ok {
		req.Env = make(map[string]string)
		for k, v := range env {
			if vs, ok := v.(string); ok {
				req.Env[k] = vs
			}
		}
	}
	if unset, ok := reqMap["unset"].([]any); ok {
		for _, u := range unset {
			if us, ok := u.(string); ok {
				req.Unset = append(req.Unset, us)
			}
		}
	}

	if err := sess.ApplyPatch(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return jsonToProto(sess.Snapshot())
}

func (s *grpcServer) KillCommand(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	sessionID, _ := reqMap["session_id"].(string)
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	sess, ok := s.app.sessions.Get(sessionID)
	if !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	cmdID, _ := reqMap["command_id"].(string)
	cmdID = strings.TrimSpace(cmdID)
	if cmdID == "" {
		return nil, status.Error(codes.InvalidArgument, "command_id is required")
	}
	current := sess.CurrentCommandID()
	if current == "" || current != cmdID {
		return nil, status.Error(codes.NotFound, "command not running")
	}
	pid := sess.CurrentProcessPID()
	if pid <= 0 {
		return nil, status.Error(codes.FailedPrecondition, "command pid not available")
	}

	_ = killProcess(pid)
	go func() {
		time.Sleep(2 * time.Second)
		_ = killProcessHard(pid)
	}()
	return jsonToProto(map[string]any{"ok": true})
}

func (s *grpcServer) QueryEvents(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	sessionID, _ := reqMap["session_id"].(string)
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if _, ok := s.app.sessions.Get(sessionID); !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}

	q := eventQueryFromMap(reqMap)
	q.SessionID = sessionID
	evs, err := s.app.store.QueryEvents(ctx, q)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return jsonToProto(evs)
}

func (s *grpcServer) SearchEvents(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	q := eventQueryFromMap(reqMap)
	if sid, ok := reqMap["session_id"].(string); ok {
		q.SessionID = strings.TrimSpace(sid)
	}
	evs, err := s.app.store.QueryEvents(ctx, q)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return jsonToProto(evs)
}

func (s *grpcServer) OutputChunk(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	sessionID, _ := reqMap["session_id"].(string)
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if _, ok := s.app.sessions.Get(sessionID); !ok {
		return nil, status.Error(codes.NotFound, "session not found")
	}
	cmdID, _ := reqMap["command_id"].(string)
	cmdID = strings.TrimSpace(cmdID)
	if cmdID == "" {
		return nil, status.Error(codes.InvalidArgument, "command_id is required")
	}
	stream, _ := reqMap["stream"].(string)
	offset := int64(0)
	if o, ok := reqMap["offset"].(float64); ok {
		offset = int64(o)
	}
	limit := int64(0)
	if l, ok := reqMap["limit"].(float64); ok {
		limit = int64(l)
	}

	chunk, total, truncated, err := s.app.store.ReadOutputChunk(ctx, cmdID, stream, offset, limit)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return jsonToProto(map[string]any{
		"command_id":  cmdID,
		"stream":      stream,
		"offset":      offset,
		"limit":       limit,
		"total_bytes": total,
		"truncated":   truncated,
		"data":        string(chunk),
		"has_more":    offset+int64(len(chunk)) < total,
	})
}

func (s *grpcServer) ListApprovals(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	if s.app.approvals == nil {
		return jsonToProto([]any{})
	}
	return jsonToProto(s.app.approvals.ListPending())
}

func (s *grpcServer) ResolveApproval(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	if s.app.approvals == nil {
		return nil, status.Error(codes.NotFound, "approvals not enabled")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	id, _ := reqMap["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	decision, _ := reqMap["decision"].(string)
	reason, _ := reqMap["reason"].(string)
	approved := strings.EqualFold(decision, "approve") || strings.EqualFold(decision, "allow")
	if ok := s.app.approvals.Resolve(id, approved, reason); !ok {
		return nil, status.Error(codes.NotFound, "approval not found")
	}
	return jsonToProto(map[string]any{"ok": true})
}

func (s *grpcServer) PolicyTest(ctx context.Context, in *structpb.Struct) (*structpb.Struct, error) {
	if s == nil || s.app == nil {
		return nil, status.Error(codes.Internal, "server not initialized")
	}
	var reqMap map[string]any
	if err := json.Unmarshal(mustProtoJSON(in), &reqMap); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}
	operation, _ := reqMap["operation"].(string)
	operation = strings.TrimSpace(operation)
	if operation == "" {
		return nil, status.Error(codes.InvalidArgument, "operation is required")
	}
	path, _ := reqMap["path"].(string)
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, status.Error(codes.InvalidArgument, "path is required")
	}

	engine := s.app.policy
	if engine == nil {
		return nil, status.Error(codes.Unavailable, "policy engine not available")
	}

	var decision policy.Decision
	op := strings.ToLower(operation)

	switch {
	case strings.HasPrefix(op, "file_") || op == "read" || op == "write" || op == "delete" || op == "create":
		opName := op
		if strings.HasPrefix(op, "file_") {
			opName = strings.TrimPrefix(op, "file_")
		}
		decision = engine.CheckFile(path, opName)

	case strings.HasPrefix(op, "net_") || op == "connect":
		host, portStr, err := net.SplitHostPort(path)
		if err != nil {
			host = path
			portStr = "443"
		}
		port := 443
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
		decision = engine.CheckNetwork(host, port)

	case op == "exec" || op == "command":
		decision = engine.CheckCommand(path, nil)

	default:
		decision = engine.CheckFile(path, op)
	}

	result := map[string]any{
		"decision":        string(decision.EffectiveDecision),
		"policy_decision": string(decision.PolicyDecision),
		"rule":            decision.Rule,
		"reason":          decision.Message,
	}
	if decision.Redirect != nil {
		result["redirect"] = map[string]any{
			"command": decision.Redirect.Command,
			"args":    decision.Redirect.Args,
		}
	}
	return jsonToProto(result)
}

// jsonToProto converts any JSON-serializable value to structpb.Struct.
func jsonToProto(v any) (*structpb.Struct, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal response")
	}
	out := &structpb.Struct{}
	if err := protojson.Unmarshal(b, out); err != nil {
		return nil, status.Error(codes.Internal, "marshal response")
	}
	return out, nil
}

// eventQueryFromMap parses event query parameters from a map.
func eventQueryFromMap(m map[string]any) types.EventQuery {
	var q types.EventQuery
	if cmdID, ok := m["command_id"].(string); ok {
		q.CommandID = cmdID
	}
	if t, ok := m["type"].(string); ok && t != "" {
		q.Types = strings.Split(t, ",")
	}
	if decision, ok := m["decision"].(string); ok && decision != "" {
		d := types.Decision(decision)
		q.Decision = &d
	}
	if pathLike, ok := m["path_like"].(string); ok {
		q.PathLike = pathLike
	}
	if domainLike, ok := m["domain_like"].(string); ok {
		q.DomainLike = domainLike
	}
	if textLike, ok := m["text_like"].(string); ok {
		q.TextLike = textLike
	}
	if limit, ok := m["limit"].(float64); ok {
		q.Limit = int(limit)
	}
	if offset, ok := m["offset"].(float64); ok {
		q.Offset = int(offset)
	}
	if order, ok := m["order"].(string); ok {
		q.Asc = order == "asc"
	}
	return q
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

// parseTraceparent parses a W3C traceparent header into trace ID and span ID.
// Format: version-trace_id-parent_id-trace_flags (e.g., 00-<32hex>-<16hex>-01)
func parseTraceparent(tp string) (traceID, spanID string, ok bool) {
	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		return "", "", false
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return "", "", false
	}
	return parts[1], parts[2], true
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
