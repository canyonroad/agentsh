package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

func New(baseURL string, apiKey string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) CreateSession(ctx context.Context, workspace, policy string) (types.Session, error) {
	var out types.Session
	reqBody := map[string]any{"workspace": workspace, "policy": policy}
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

func (c *Client) Exec(ctx context.Context, sessionID string, req types.ExecRequest) (types.ExecResponse, error) {
	var out types.ExecResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/sessions/"+url.PathEscape(sessionID)+"/exec", nil, req, &out); err != nil {
		return out, err
	}
	return out, nil
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
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
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
