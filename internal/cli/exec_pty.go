package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/ptygrpc"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/gorilla/websocket"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type execPTYRequest struct {
	Command        string
	Args           []string
	Argv0          string
	WorkingDir     string
	Env            map[string]string
	Timeout        string
	Stdin          string
	AutoCreateRoot string
	NoDetectRoot   bool
	ProjectRoot    string
}

type ptyTermState struct {
	state *term.State
}

type ptyDeps struct {
	isTTY   func(fd int) bool
	makeRaw func(fd int) (*ptyTermState, error)
	restore func(fd int, st *ptyTermState) error
	getSize func(fd int) (cols int, rows int, err error)
}

func defaultPTYDeps() ptyDeps {
	return ptyDeps{
		isTTY: term.IsTerminal,
		makeRaw: func(fd int) (*ptyTermState, error) {
			st, err := term.MakeRaw(fd)
			if err != nil {
				return nil, err
			}
			return &ptyTermState{state: st}, nil
		},
		restore: func(fd int, st *ptyTermState) error {
			if st == nil || st.state == nil {
				return nil
			}
			return term.Restore(fd, st.state)
		},
		getSize: term.GetSize,
	}
}

var execPTYRunner = execPTY
var execPTYGRPCRunner = execPTYGRPC
var execPTYWSRunner = execPTYWS

func ptyDenyMode() string {
	return strings.ToLower(strings.TrimSpace(os.Getenv("AGENTSH_PTY_DENY_MODE")))
}

func isPolicyDenyMessage(msg string) bool {
	msg = strings.ToLower(strings.TrimSpace(msg))
	return strings.Contains(msg, "command denied")
}

func ptyDeniedExitError(sessionID string, req execPTYRequest, msg string) error {
	if strings.EqualFold(ptyDenyMode(), "error") {
		return nil
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		msg = "command denied by policy"
	}
	hint := fmt.Sprintf("Tip: re-run without --pty to see policy details:\nagentsh exec --output json --events=blocked %s -- %s ...", sessionID, strings.TrimSpace(req.Command))
	return &ExitError{code: 126, message: msg + "\n" + hint}
}

func execPTY(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest) error {
	return execPTYWithDeps(ctx, cfg, sessionID, req, defaultPTYDeps())
}

func execPTYWithDeps(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest, deps ptyDeps) error {
	if cfg == nil {
		return errors.New("client config is required")
	}
	timeout := strings.TrimSpace(req.Timeout)
	if timeout != "" {
		d, err := time.ParseDuration(timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid --timeout %q", req.Timeout)
		}
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	transport := strings.ToLower(strings.TrimSpace(cfg.transport))
	if transport == "" {
		transport = "http"
	}

	try := func() error {
		switch transport {
		case "grpc":
			return execPTYGRPCRunner(ctx, cfg, sessionID, req, deps)
		case "http":
			return execPTYWSRunner(ctx, cfg, sessionID, req, deps)
		default:
			return fmt.Errorf("unknown transport %q (expected http|grpc)", cfg.transport)
		}
	}

	err := try()
	if err == nil {
		return nil
	}
	if !autoDisabled() && isConnectionError(err) {
		if startErr := ensureServerRunning(ctx, cfg.serverAddr, os.Stderr); startErr == nil {
			err = try()
		} else {
			return fmt.Errorf("server unreachable (%v); auto-start failed: %w", err, startErr)
		}
	}
	if err == nil {
		return nil
	}
	if !autoDisabled() && errors.Is(err, errPTYSessionNotFound) {
		autoCreateRoot := strings.TrimSpace(req.AutoCreateRoot)
		if autoCreateRoot == "" {
			autoCreateRoot, _ = os.Getwd()
		}
		if autoCreateRoot != "" {
			cl, clErr := client.NewForCLI(client.CLIOptions{
				HTTPBaseURL:   cfg.serverAddr,
				GRPCAddr:      cfg.grpcAddr,
				APIKey:        cfg.apiKey,
				Transport:     cfg.transport,
				ClientTimeout: cfg.getClientTimeout(),
			})
			if clErr == nil {
				createReq := types.CreateSessionRequest{
					ID:        sessionID,
					Workspace: autoCreateRoot,
				}
				if req.NoDetectRoot {
					falseVal := false
					createReq.DetectProjectRoot = &falseVal
				}
				if req.ProjectRoot != "" {
					createReq.ProjectRoot = req.ProjectRoot
				}
				if _, createErr := cl.CreateSessionWithRequest(ctx, createReq); createErr == nil {
					err = try()
				}
			}
		}
	}
	return err
}

var errPTYSessionNotFound = errors.New("pty: session not found")

func maybeRawTerminal(deps ptyDeps) (restore func(), rows, cols uint16, isTTY bool, err error) {
	stdinFD := int(os.Stdin.Fd())
	stdoutFD := int(os.Stdout.Fd())
	isTTY = deps.isTTY(stdinFD) && deps.isTTY(stdoutFD)
	if !isTTY {
		return func() {}, 0, 0, false, nil
	}
	st, err := deps.makeRaw(stdinFD)
	if err != nil {
		return func() {}, 0, 0, false, err
	}
	colsI, rowsI, _ := deps.getSize(stdoutFD)
	restore = func() { _ = deps.restore(stdinFD, st) }
	return restore, uint16(rowsI), uint16(colsI), true, nil
}

func execPTYGRPC(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest, deps ptyDeps) error {
	restore, rows, cols, isTTY, err := maybeRawTerminal(deps)
	if err != nil {
		return err
	}
	defer restore()

	maybeMapDeny := func(err error) error {
		if err == nil {
			return nil
		}
		if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied && isPolicyDenyMessage(st.Message()) {
			if ee := ptyDeniedExitError(sessionID, req, st.Message()); ee != nil {
				return ee
			}
		}
		return err
	}

	addr := strings.TrimSpace(cfg.grpcAddr)
	if addr == "" {
		addr = "127.0.0.1:9090"
	}
	// Mirror client.NewGRPC addr normalization.
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			addr = u.Host
		}
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	if strings.TrimSpace(cfg.apiKey) != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-api-key", strings.TrimSpace(cfg.apiKey))
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	c := ptygrpc.NewAgentshPTYClient(conn)
	stream, err := c.ExecPTY(runCtx)
	if err != nil {
		return maybeMapDeny(err)
	}

	start := &ptygrpc.ExecPTYStart{
		SessionId:  sessionID,
		Command:    req.Command,
		Args:       req.Args,
		Argv0:      req.Argv0,
		WorkingDir: req.WorkingDir,
		Env:        req.Env,
		Rows:       uint32(rows),
		Cols:       uint32(cols),
	}
	if err := stream.Send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Start{Start: start}}); err != nil {
		// In bidi streams the "real" RPC status is often only surfaced on Recv.
		// If the server rejects immediately (before reading Start), Send can return EOF.
		if errors.Is(err, io.EOF) {
			_, recvErr := stream.Recv()
			if recvErr != nil {
				return maybeMapDeny(recvErr)
			}
		}
		return maybeMapDeny(err)
	}

	var sendMu sync.Mutex
	send := func(m *ptygrpc.ExecPTYClientMsg) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}

	// Forward signals.
	sigCh := make(chan os.Signal, 16)
	signal.Notify(sigCh, signalsToNotify()...)
	defer signal.Stop(sigCh)

	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case sig := <-sigCh:
				if isWinchSignal(sig) {
					if !isTTY {
						continue
					}
					colsI, rowsI, _ := deps.getSize(int(os.Stdout.Fd()))
					_ = send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Resize{Resize: &ptygrpc.ExecPTYResize{Rows: uint32(rowsI), Cols: uint32(colsI)}}})
					continue
				}
				name := signalName(sig)
				if name != "" {
					_ = send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Signal{Signal: &ptygrpc.ExecPTYSignal{Name: name}}})
				}
			}
		}
	}()

	// Stdin -> server.
	go func() {
		if strings.TrimSpace(req.Stdin) != "" {
			_ = send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Stdin{Stdin: &ptygrpc.ExecPTYStdin{Data: []byte(req.Stdin)}}})
		}
		buf := make([]byte, 32*1024)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				if sendErr := send(&ptygrpc.ExecPTYClientMsg{Msg: &ptygrpc.ExecPTYClientMsg_Stdin{Stdin: &ptygrpc.ExecPTYStdin{Data: b}}}); sendErr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			if st, ok := status.FromError(err); ok {
				if st.Code() == codes.NotFound {
					return errPTYSessionNotFound
				}
				if st.Code() == codes.PermissionDenied && isPolicyDenyMessage(st.Message()) {
					if ee := ptyDeniedExitError(sessionID, req, st.Message()); ee != nil {
						return ee
					}
				}
			}
			return err
		}
		switch m := msg.Msg.(type) {
		case *ptygrpc.ExecPTYServerMsg_Output:
			_, _ = os.Stdout.Write(m.Output.Data)
		case *ptygrpc.ExecPTYServerMsg_Exit:
			cancelRun()
			code := int(m.Exit.ExitCode)
			if code != 0 {
				return &ExitError{code: code}
			}
			return nil
		case *ptygrpc.ExecPTYServerMsg_Error:
			cancelRun()
			if strings.EqualFold(strings.TrimSpace(m.Error.Code), "NOT_FOUND") {
				return errPTYSessionNotFound
			}
			return fmt.Errorf("%s", strings.TrimSpace(m.Error.Message))
		default:
			// ignore
		}
	}
}

type ptyWSStart struct {
	Type       string            `json:"type,omitempty"`
	Command    string            `json:"command"`
	Args       []string          `json:"args,omitempty"`
	Argv0      string            `json:"argv0,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Rows       uint16            `json:"rows,omitempty"`
	Cols       uint16            `json:"cols,omitempty"`
}

type ptyWSControl struct {
	Type string `json:"type"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Name string `json:"name,omitempty"`
}

type ptyWSExit struct {
	Type     string `json:"type"`
	ExitCode int    `json:"exit_code"`
}

type ptyWSError struct {
	Type    string `json:"type"`
	Code    int    `json:"code,omitempty"`
	Message string `json:"message"`
}

func execPTYWS(ctx context.Context, cfg *clientConfig, sessionID string, req execPTYRequest, deps ptyDeps) error {
	restore, rows, cols, isTTY, err := maybeRawTerminal(deps)
	if err != nil {
		return err
	}
	defer restore()

	wsURL, dialer, err := ptyWSURLAndDialer(cfg.serverAddr, "/api/v1/sessions/"+url.PathEscape(sessionID)+"/pty")
	if err != nil {
		return err
	}
	h := http.Header{}
	if strings.TrimSpace(cfg.apiKey) != "" {
		h.Set("X-API-Key", strings.TrimSpace(cfg.apiKey))
	}

	conn, resp, err := dialer.DialContext(ctx, wsURL, h)
	if err != nil {
		// If the server isn't reachable yet, prefer a connection error.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return errPTYSessionNotFound
		}
		return err
	}
	defer conn.Close()

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	var writeMu sync.Mutex
	writeBin := func(b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, b)
	}
	writeText := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		b, _ := json.Marshal(v)
		return conn.WriteMessage(websocket.TextMessage, b)
	}

	go func() {
		<-runCtx.Done()
		writeMu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(250*time.Millisecond))
		writeMu.Unlock()
		_ = conn.Close()
	}()

	if err := writeText(ptyWSStart{
		Type:       "start",
		Command:    req.Command,
		Args:       req.Args,
		Argv0:      req.Argv0,
		WorkingDir: req.WorkingDir,
		Env:        req.Env,
		Rows:       rows,
		Cols:       cols,
	}); err != nil {
		return err
	}

	// Forward signals.
	sigCh := make(chan os.Signal, 16)
	signal.Notify(sigCh, signalsToNotify()...)
	defer signal.Stop(sigCh)
	go func() {
		if !isTTY {
			return
		}
		for {
			select {
			case <-runCtx.Done():
				return
			case sig := <-sigCh:
				if isWinchSignal(sig) {
					colsI, rowsI, _ := deps.getSize(int(os.Stdout.Fd()))
					_ = writeText(ptyWSControl{Type: "resize", Rows: uint16(rowsI), Cols: uint16(colsI)})
					continue
				}
				name := signalName(sig)
				if name != "" {
					_ = writeText(ptyWSControl{Type: "signal", Name: name})
				}
			}
		}
	}()

	// Stdin -> server.
	go func() {
		if strings.TrimSpace(req.Stdin) != "" {
			_ = writeBin([]byte(req.Stdin))
		}
		buf := make([]byte, 32*1024)
		for {
			n, rerr := os.Stdin.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				if werr := writeBin(b); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			return err
		}
		switch mt {
		case websocket.BinaryMessage:
			_, _ = os.Stdout.Write(data)
		case websocket.TextMessage:
			var base struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &base) != nil {
				continue
			}
			switch base.Type {
			case "exit":
				var ex ptyWSExit
				if json.Unmarshal(data, &ex) != nil {
					return nil
				}
				cancelRun()
				if ex.ExitCode != 0 {
					return &ExitError{code: ex.ExitCode}
				}
				return nil
			case "error":
				var ee ptyWSError
				_ = json.Unmarshal(data, &ee)
				cancelRun()
				if ee.Code == http.StatusNotFound && strings.Contains(strings.ToLower(ee.Message), "session") {
					return errPTYSessionNotFound
				}
				if ee.Code == http.StatusForbidden && isPolicyDenyMessage(ee.Message) {
					if ex := ptyDeniedExitError(sessionID, req, ee.Message); ex != nil {
						return ex
					}
				}
				return fmt.Errorf("%s", strings.TrimSpace(ee.Message))
			default:
				// ignore
			}
		default:
			// ignore
		}
	}
}

func ptyWSURLAndDialer(baseURL, path string) (string, *websocket.Dialer, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return "", nil, fmt.Errorf("server base url is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "unix":
		sock := u.Path
		if sock == "" {
			sock = u.Host
		} else if u.Host != "" {
			sock = u.Host + u.Path
		}
		sock = strings.TrimSpace(sock)
		if sock == "" {
			return "", nil, fmt.Errorf("unix socket path is empty")
		}
		d := &websocket.Dialer{
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}
		return "ws://unix" + path, d, nil
	case "http", "https":
		wsScheme := "ws"
		if strings.EqualFold(u.Scheme, "https") {
			wsScheme = "wss"
		}
		host := u.Host
		if host == "" {
			host = u.Path
		}
		if host == "" {
			return "", nil, fmt.Errorf("server host is empty")
		}
		prefix := ""
		if u.Host != "" {
			prefix = strings.TrimRight(u.Path, "/")
			if prefix == "/" {
				prefix = ""
			}
		}
		return wsScheme + "://" + host + prefix + path, websocket.DefaultDialer, nil
	default:
		return "", nil, fmt.Errorf("unsupported server scheme %q", u.Scheme)
	}
}
