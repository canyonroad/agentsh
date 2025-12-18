package api

import (
	"bytes"
	"io"
	"strings"
	"syscall"
	"time"

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

	run, httpCode, err := s.app.startPTY(stream.Context(), start.SessionId, ptyStartParams{
		Command:    start.Command,
		Args:       start.Args,
		Argv0:      start.Argv0,
		WorkingDir: start.WorkingDir,
		Env:        start.Env,
		Rows:       uint16(start.Rows),
		Cols:       uint16(start.Cols),
	})
	if err != nil {
		switch httpCode {
		case 400:
			return status.Error(codes.InvalidArgument, err.Error())
		case 403:
			return status.Error(codes.PermissionDenied, err.Error())
		case 404:
			return status.Error(codes.NotFound, err.Error())
		default:
			return status.Error(codes.Internal, err.Error())
		}
	}
	defer run.unlock()

	type waitRes struct {
		code int
		err  error
	}
	waitCh := make(chan waitRes, 1)
	go func() {
		code, werr := run.ps.Wait()
		waitCh <- waitRes{code: code, err: werr}
	}()

	// Client -> PTY (best-effort; handler will return after exit even if client keeps stdin open).
	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				// Client closed send-side (stdin) is normal; don't kill the process.
				if rerr == io.EOF {
					return
				}
				_ = run.ps.Signal(syscall.SIGKILL)
				return
			}
			switch {
			case msg.GetStdin() != nil:
				_, _ = run.ps.Write(msg.GetStdin().Data)
			case msg.GetResize() != nil:
				r := msg.GetResize()
				_ = run.ps.Resize(uint16(r.Rows), uint16(r.Cols))
			case msg.GetSignal() != nil:
				sigName := strings.TrimSpace(strings.ToUpper(msg.GetSignal().Name))
				switch sigName {
				case "SIGINT":
					_ = run.ps.Signal(syscall.SIGINT)
				case "SIGTERM":
					_ = run.ps.Signal(syscall.SIGTERM)
				case "SIGHUP":
					_ = run.ps.Signal(syscall.SIGHUP)
				case "SIGQUIT":
					_ = run.ps.Signal(syscall.SIGQUIT)
				}
			default:
				// Ignore unknown/empty messages (including repeated start).
			}
		}
	}()

	var out bytes.Buffer
	var outTotal int64
	outTrunc := false
	appendOut := func(b []byte) {
		if len(b) == 0 {
			return
		}
		outTotal += int64(len(b))
		if int64(out.Len()) >= defaultMaxOutputBytes {
			outTrunc = true
			return
		}
		remain := defaultMaxOutputBytes - int64(out.Len())
		if int64(len(b)) <= remain {
			_, _ = out.Write(b)
		} else {
			_, _ = out.Write(b[:remain])
			outTrunc = true
		}
	}

	var sendErr error
	for b := range run.ps.Output() {
		appendOut(b)
		if sendErr == nil {
			if err := stream.Send(&ptygrpc.ExecPTYServerMsg{
				Msg: &ptygrpc.ExecPTYServerMsg_Output{
					Output: &ptygrpc.ExecPTYOutput{Data: b},
				},
			}); err != nil {
				// Client hung up; stop the process and keep draining output so Wait can complete.
				sendErr = err
				_ = run.ps.Signal(syscall.SIGKILL)
			}
		}
	}

	res := <-waitCh
	s.app.finishPTY(stream.Context(), run, res.code, run.started, res.err, out.Bytes(), outTotal, outTrunc)
	if res.err != nil {
		return status.Error(codes.Internal, res.err.Error())
	}
	if sendErr != nil {
		return sendErr
	}

	// Best-effort: send exit.
	if err := stream.Send(&ptygrpc.ExecPTYServerMsg{
		Msg: &ptygrpc.ExecPTYServerMsg_Exit{
			Exit: &ptygrpc.ExecPTYExit{
				ExitCode:   int32(res.code),
				DurationMs: time.Since(run.started).Milliseconds(),
			},
		},
	}); err != nil {
		return err
	}
	return nil
}
