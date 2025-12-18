package api

import (
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/agentsh/agentsh/internal/pty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/agentsh/agentsh/pkg/ptygrpc"
)

type ptyGRPCServer struct {
	app *App
	ptygrpc.UnimplementedAgentshPTYServer
}

func (s *ptyGRPCServer) ExecPTY(stream ptygrpc.AgentshPTY_ExecPTYServer) error {
	if s == nil || s.app == nil {
		return status.Error(codes.Unimplemented, "pty not implemented")
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil {
		return status.Error(codes.InvalidArgument, "start is required as the first message")
	}
	if strings.TrimSpace(start.SessionId) == "" {
		return status.Error(codes.InvalidArgument, "session_id is required")
	}
	if strings.TrimSpace(start.Command) == "" {
		return status.Error(codes.InvalidArgument, "command is required")
	}

	sess, ok := s.app.sessions.Get(start.SessionId)
	if !ok {
		return status.Error(codes.NotFound, "session not found")
	}

	unlock := sess.LockExec()
	defer unlock()

	workdir, err := resolveWorkingDir(sess, strings.TrimSpace(start.WorkingDir))
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	env := mergeEnv(os.Environ(), sess, start.Env)

	eng := pty.New()
	ps, err := eng.Start(stream.Context(), pty.StartRequest{
		Command: start.Command,
		Args:    start.Args,
		Argv0:   strings.TrimSpace(start.Argv0),
		Dir:     workdir,
		Env:     env,
		InitialSize: pty.Winsize{
			Rows: uint16(start.Rows),
			Cols: uint16(start.Cols),
		},
	})
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	started := time.Now()

	type waitRes struct {
		code int
		err  error
	}
	waitCh := make(chan waitRes, 1)
	go func() {
		code, werr := ps.Wait()
		waitCh <- waitRes{code: code, err: werr}
	}()

	// Client -> PTY (best-effort; handler will return after exit even if client keeps stdin open).
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				return
			}
			switch {
			case msg.GetStdin() != nil:
				_, _ = ps.Write(msg.GetStdin().Data)
			case msg.GetResize() != nil:
				r := msg.GetResize()
				_ = ps.Resize(uint16(r.Rows), uint16(r.Cols))
			case msg.GetSignal() != nil:
				sigName := strings.TrimSpace(strings.ToUpper(msg.GetSignal().Name))
				switch sigName {
				case "SIGINT":
					_ = ps.Signal(syscall.SIGINT)
				case "SIGTERM":
					_ = ps.Signal(syscall.SIGTERM)
				case "SIGHUP":
					_ = ps.Signal(syscall.SIGHUP)
				case "SIGQUIT":
					_ = ps.Signal(syscall.SIGQUIT)
				}
			default:
				// Ignore unknown/empty messages (including repeated start).
			}
		}
	}()

	for b := range ps.Output() {
		if err := stream.Send(&ptygrpc.ExecPTYServerMsg{
			Msg: &ptygrpc.ExecPTYServerMsg_Output{
				Output: &ptygrpc.ExecPTYOutput{Data: b},
			},
		}); err != nil {
			// Client hung up; stop the process and propagate the send error.
			_ = ps.Signal(syscall.SIGKILL)
			return err
		}
	}

	res := <-waitCh
	if res.err != nil {
		return status.Error(codes.Internal, res.err.Error())
	}

	// Best-effort: send exit.
	if err := stream.Send(&ptygrpc.ExecPTYServerMsg{
		Msg: &ptygrpc.ExecPTYServerMsg_Exit{
			Exit: &ptygrpc.ExecPTYExit{
				ExitCode:   int32(res.code),
				DurationMs: time.Since(started).Milliseconds(),
			},
		},
	}); err != nil {
		return err
	}
	return nil
}
