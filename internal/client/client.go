package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type HTTPError struct {
	Method     string
	Path       string
	Status     string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if msg == "" {
		return fmt.Sprintf("%s %s: %s", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("%s %s: %s: %s", e.Method, e.Path, e.Status, msg)
}

// DefaultClientTimeout is the default HTTP client timeout for API requests.
const DefaultClientTimeout = 30 * time.Second

func New(baseURL string, apiKey string) *Client {
	return NewWithTimeout(baseURL, apiKey, DefaultClientTimeout)
}

func NewWithTimeout(baseURL string, apiKey string, timeout time.Duration) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	if timeout <= 0 {
		timeout = DefaultClientTimeout
	}
	hc := &http.Client{Timeout: timeout}
	if u, err := url.Parse(baseURL); err == nil && strings.EqualFold(u.Scheme, "unix") {
		sock := u.Path
		if sock == "" {
			sock = u.Host
		} else if u.Host != "" {
			sock = u.Host + u.Path
		}
		sock = strings.TrimSpace(sock)
		if sock != "" {
			dialer := &net.Dialer{}
			hc.Transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, "unix", sock)
				},
			}
			baseURL = "http://unix"
		}
	}
	return &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: hc,
	}
}

func (c *Client) CreateSession(ctx context.Context, workspace, policy string) (types.Session, error) {
	var out types.Session
	reqBody := types.CreateSessionRequest{Workspace: workspace, Policy: policy}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sessions", nil, reqBody, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) CreateSessionWithID(ctx context.Context, id, workspace, policy string) (types.Session, error) {
	var out types.Session
	reqBody := types.CreateSessionRequest{ID: id, Workspace: workspace, Policy: policy}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sessions", nil, reqBody, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) CreateSessionWithRequest(ctx context.Context, req types.CreateSessionRequest) (types.Session, error) {
	var out types.Session
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sessions", nil, req, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) CreateSessionWithProfile(ctx context.Context, profile string) (types.Session, error) {
	var out types.Session
	reqBody := types.CreateSessionRequest{Profile: profile}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sessions", nil, reqBody, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) ListSessions(ctx context.Context) ([]types.Session, error) {
	var out []types.Session
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/sessions", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetSession(ctx context.Context, id string) (types.Session, error) {
	var out types.Session
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/sessions/"+url.PathEscape(id), nil, nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) DestroySession(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, "/api/v1/sessions/"+url.PathEscape(id), nil, nil, nil)
}

func (c *Client) PatchSession(ctx context.Context, id string, req types.SessionPatchRequest) (types.Session, error) {
	var out types.Session
	if err := c.doJSON(ctx, http.MethodPatch, "/api/v1/sessions/"+url.PathEscape(id), nil, req, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error) {
	var out types.ExecResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sessions/"+url.PathEscape(sessionID)+"/exec", nil, req, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) KillCommand(ctx context.Context, sessionID string, commandID string) error {
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/kill/" + url.PathEscape(commandID)
	return c.doJSON(ctx, http.MethodPost, path, nil, map[string]any{}, nil)
}

func (c *Client) QuerySessionEvents(ctx context.Context, sessionID string, q url.Values) ([]types.Event, error) {
	var out []types.Event
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/history"
	if err := c.doJSON(ctx, http.MethodGet, path, q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) SearchEvents(ctx context.Context, q url.Values) ([]types.Event, error) {
	var out []types.Event
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/events/search", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) OutputChunk(ctx context.Context, sessionID, commandID string, stream string, offset, limit int64) (map[string]any, error) {
	q := url.Values{}
	q.Set("stream", stream)
	q.Set("offset", fmt.Sprintf("%d", offset))
	q.Set("limit", fmt.Sprintf("%d", limit))
	var out map[string]any
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/output/" + url.PathEscape(commandID)
	if err := c.doJSON(ctx, http.MethodGet, path, q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ListApprovals(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/approvals", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) ResolveApproval(ctx context.Context, id string, decision string, reason string) error {
	body := map[string]any{"decision": decision, "reason": reason}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/approvals/"+url.PathEscape(id), nil, body, nil)
}

func (c *Client) PolicyTest(ctx context.Context, sessionID, operation, path string) (map[string]any, error) {
	body := map[string]any{
		"operation": operation,
		"path":      path,
	}
	if sessionID != "" {
		body["session_id"] = sessionID
	}
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/policy/test", nil, body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetProxyStatus(ctx context.Context, sessionID string) (map[string]any, error) {
	var out map[string]any
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/proxy"
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) WrapInit(ctx context.Context, sessionID string, req types.WrapInitRequest) (types.WrapInitResponse, error) {
	var out types.WrapInitResponse
	path := "/api/v1/sessions/" + url.PathEscape(sessionID) + "/wrap-init"
	if err := c.doJSON(ctx, http.MethodPost, path, nil, req, &out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) StreamSessionEvents(ctx context.Context, sessionID string) (io.ReadCloser, error) {
	u := c.baseURL + "/api/v1/sessions/" + url.PathEscape(sessionID) + "/events"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	c.addAuth(req)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		return nil, fmt.Errorf("stream events: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return resp.Body, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, q url.Values, body any, out any) error {
	u := c.baseURL + path
	if q != nil && len(q) > 0 {
		u += "?" + q.Encode()
	}

	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	c.addAuth(req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return &HTTPError{
			Method:     method,
			Path:       path,
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Body:       string(b),
		}
	}

	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) addAuth(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
}

// ListTaints lists all tainted processes.
// Note: Server endpoint not yet implemented.
func (c *Client) ListTaints(ctx context.Context, sessionID string) ([]types.TaintInfo, error) {
	var out []types.TaintInfo
	path := "/api/v1/taints"
	q := url.Values{}
	if sessionID != "" {
		q.Set("session_id", sessionID)
	}
	if err := c.doJSON(ctx, http.MethodGet, path, q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetTaint gets taint info for a specific PID.
// Note: Server endpoint not yet implemented.
func (c *Client) GetTaint(ctx context.Context, pid int) (*types.TaintInfo, error) {
	var out types.TaintInfo
	path := fmt.Sprintf("/api/v1/taints/%d", pid)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTaintTrace gets the full ancestry trace for a PID.
// Note: Server endpoint not yet implemented.
func (c *Client) GetTaintTrace(ctx context.Context, pid int) (*types.TaintTrace, error) {
	var out types.TaintTrace
	path := fmt.Sprintf("/api/v1/taints/%d/trace", pid)
	if err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WatchTaints watches for taint events via SSE.
// Note: Server endpoint not yet implemented.
func (c *Client) WatchTaints(ctx context.Context, agentOnly bool, handler func(types.TaintEvent)) error {
	path := "/api/v1/taints/events"
	if agentOnly {
		path += "?agent_only=true"
	}

	u := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	c.addAuth(req)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		return fmt.Errorf("watch taints: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}

	// Parse SSE stream
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()

		// SSE data lines start with "data: "
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")
		if data == "" {
			continue
		}

		var event types.TaintEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue // Skip malformed events
		}
		handler(event)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
