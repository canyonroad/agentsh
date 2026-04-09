package proxy

import (
	"bytes"
	"io"
	"net/http"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
)

// CredsSubHook performs credential substitution using a credsub.Table.
// PreHook replaces fake credentials with real ones in request bodies.
// PostHook replaces real credentials with fakes in response bodies.
type CredsSubHook struct {
	table *credsub.Table
}

// NewCredsSubHook returns a CredsSubHook that uses the given table.
func NewCredsSubHook(table *credsub.Table) *CredsSubHook {
	return &CredsSubHook{table: table}
}

func (h *CredsSubHook) Name() string { return "creds-sub" }

// PreHook replaces fake credentials with real ones in the request body.
func (h *CredsSubHook) PreHook(r *http.Request, _ *RequestContext) error {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil // best-effort
	}

	replaced := h.table.ReplaceFakeToReal(body)
	r.Body = io.NopCloser(bytes.NewReader(replaced))
	r.ContentLength = int64(len(replaced))
	return nil
}

// PostHook replaces real credentials with fakes in the response body.
func (h *CredsSubHook) PostHook(resp *http.Response, _ *RequestContext) error {
	if resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil // best-effort
	}

	replaced := h.table.ReplaceRealToFake(body)
	resp.Body = io.NopCloser(bytes.NewReader(replaced))
	resp.ContentLength = int64(len(replaced))
	return nil
}
