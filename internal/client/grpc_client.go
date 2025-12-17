package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type GRPCClient struct {
	addr   string
	apiKey string
	conn   *grpc.ClientConn
}

func NewGRPC(addr string, apiKey string) (*GRPCClient, error) {
	a := strings.TrimSpace(addr)
	if strings.Contains(a, "://") {
		if u, err := url.Parse(a); err == nil {
			if u.Host != "" {
				a = u.Host
			}
		}
	}
	if a == "" {
		return nil, fmt.Errorf("grpc addr is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, a, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &GRPCClient{addr: a, apiKey: apiKey, conn: conn}, nil
}

func (c *GRPCClient) CreateSession(ctx context.Context, workspace, policy string) (types.Session, error) {
	return c.createSession(ctx, "", workspace, policy)
}

func (c *GRPCClient) CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	return c.createSession(ctx, id, workspace, policy)
}

func (c *GRPCClient) createSession(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	var out types.Session
	reqBody := map[string]any{
		"workspace": workspace,
		"policy":    policy,
	}
	if strings.TrimSpace(id) != "" {
		reqBody["id"] = id
	}
	in, err := jsonToStruct(reqBody)
	if err != nil {
		return out, err
	}
	resp := &structpb.Struct{}
	if err := c.invokeUnary(ctx, "/agentsh.v1.Agentsh/CreateSession", in, resp); err != nil {
		return out, err
	}
	b, _ := protojson.Marshal(resp)
	_ = json.Unmarshal(b, &out)
	return out, nil
}

func (c *GRPCClient) Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error) {
	var out types.ExecResponse
	body := map[string]any{
		"session_id":     sessionID,
		"command":        req.Command,
		"args":           req.Args,
		"working_dir":    req.WorkingDir,
		"timeout":        req.Timeout,
		"stdin":          req.Stdin,
		"env":            req.Env,
		"include_events": req.IncludeEvents,
	}
	in, err := jsonToStruct(body)
	if err != nil {
		return out, err
	}
	resp := &structpb.Struct{}
	if err := c.invokeUnary(ctx, "/agentsh.v1.Agentsh/Exec", in, resp); err != nil {
		return out, err
	}
	b, _ := protojson.Marshal(resp)
	_ = json.Unmarshal(b, &out)
	return out, nil
}

func (c *GRPCClient) ExecStream(ctx context.Context, sessionID string, req types.ExecRequest) (io.ReadCloser, error) {
	body := map[string]any{
		"session_id":  sessionID,
		"command":     req.Command,
		"args":        req.Args,
		"working_dir": req.WorkingDir,
		"timeout":     req.Timeout,
		"stdin":       req.Stdin,
		"env":         req.Env,
	}
	in, err := jsonToStruct(body)
	if err != nil {
		return nil, err
	}
	stream, err := c.newServerStream(ctx, "/agentsh.v1.Agentsh/ExecStream", in)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer func() { _ = stream.CloseSend() }()

		w := bufio.NewWriter(pw)
		defer w.Flush()

		for {
			msg := &structpb.Struct{}
			if err := stream.RecvMsg(msg); err != nil {
				if err == io.EOF {
					return
				}
				_ = pw.CloseWithError(err)
				return
			}
			b, _ := protojson.Marshal(msg)
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			ev, _ := m["event"].(string)
			if ev == "" {
				ev = "message"
			}
			delete(m, "event")
			data, _ := json.Marshal(m)
			_, _ = fmt.Fprintf(w, "event: %s\n", strings.TrimSpace(ev))
			_, _ = fmt.Fprintf(w, "data: %s\n\n", strings.TrimSpace(string(data)))
			_ = w.Flush()
		}
	}()
	return pr, nil
}

func (c *GRPCClient) StreamSessionEvents(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	in, err := jsonToStruct(map[string]any{"session_id": sessionID})
	if err != nil {
		return nil, err
	}
	stream, err := c.newServerStream(ctx, "/agentsh.v1.Agentsh/EventsTail", in)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		defer func() { _ = stream.CloseSend() }()

		w := bufio.NewWriter(pw)
		defer w.Flush()

		for {
			msg := &structpb.Struct{}
			if err := stream.RecvMsg(msg); err != nil {
				if err == io.EOF {
					return
				}
				_ = pw.CloseWithError(err)
				return
			}
			b, _ := protojson.Marshal(msg)
			trim := strings.TrimSpace(string(b))
			// If server sends {"event":"ready"} for parity with SSE, output {} like SSE clients expect.
			if trim == `{"event":"ready"}` {
				trim = "{}"
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", trim)
			_ = w.Flush()
		}
	}()
	return pr, nil
}

func (c *GRPCClient) invokeUnary(ctx context.Context, method string, in *structpb.Struct, out *structpb.Struct) error {
	if c == nil || c.conn == nil {
		return fmt.Errorf("grpc client not initialized")
	}
	ctx = c.withAuth(ctx)
	return c.conn.Invoke(ctx, method, in, out)
}

func (c *GRPCClient) newServerStream(ctx context.Context, method string, in *structpb.Struct) (grpc.ClientStream, error) {
	if c == nil || c.conn == nil {
		return nil, fmt.Errorf("grpc client not initialized")
	}
	ctx = c.withAuth(ctx)
	desc := &grpc.StreamDesc{ServerStreams: true, ClientStreams: false}
	cs, err := c.conn.NewStream(ctx, desc, method)
	if err != nil {
		return nil, err
	}
	if err := cs.SendMsg(in); err != nil {
		return nil, err
	}
	if err := cs.CloseSend(); err != nil {
		return nil, err
	}
	return cs, nil
}

func (c *GRPCClient) withAuth(ctx context.Context) context.Context {
	if strings.TrimSpace(c.apiKey) == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "x-api-key", c.apiKey)
}

func jsonToStruct(v any) (*structpb.Struct, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := &structpb.Struct{}
	if err := protojson.Unmarshal(b, out); err != nil {
		return nil, err
	}
	return out, nil
}
