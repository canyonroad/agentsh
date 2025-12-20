package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOutputChunkSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stream") != "stdout" || r.URL.Query().Get("offset") != "5" || r.URL.Query().Get("limit") != "3" {
			t.Fatalf("unexpected query: %v", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": "abc", "total": 10})
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	out, err := c.OutputChunk(context.Background(), "sid", "cid", "stdout", 5, 3)
	if err != nil {
		t.Fatalf("OutputChunk error: %v", err)
	}
	if out["data"] != "abc" {
		t.Fatalf("unexpected body: %+v", out)
	}
}

func TestOutputChunkNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusTeapot)
	}))
	defer srv.Close()

	c := New(srv.URL, "")
	if _, err := c.OutputChunk(context.Background(), "sid", "cid", "stderr", 0, 1); err == nil {
		t.Fatalf("expected error on non-2xx")
	}
}
