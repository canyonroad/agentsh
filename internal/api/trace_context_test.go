package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
)

func TestParseTraceparent_Valid(t *testing.T) {
	traceID, spanID, flags, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	if !ok {
		t.Fatal("expected ok")
	}
	if traceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("traceID = %q", traceID)
	}
	if spanID != "b7ad6b7169203331" {
		t.Errorf("spanID = %q", spanID)
	}
	if flags != "01" {
		t.Errorf("flags = %q", flags)
	}
}

func TestParseTraceparent_UnsampledFlags(t *testing.T) {
	_, _, flags, ok := parseTraceparent("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00")
	if !ok {
		t.Fatal("expected ok")
	}
	if flags != "00" {
		t.Errorf("flags = %q, want %q", flags, "00")
	}
}

func TestParseTraceparent_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"too few parts", "00-abc-def"},
		{"too many parts", "00-abc-def-01-extra"},
		{"short trace_id", "00-0af765-b7ad6b7169203331-01"},
		{"short span_id", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b-01"},
		{"non-hex trace_id", "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-b7ad6b7169203331-01"},
		{"non-hex span_id", "00-0af7651916cd43dd8448eb211c80319c-zzzzzzzzzzzzzzzz-01"},
		{"non-hex flags", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-zz"},
		{"all-zero trace_id", "00-00000000000000000000000000000000-b7ad6b7169203331-01"},
		{"all-zero span_id", "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01"},
		{"empty", ""},
		{"reserved version ff", "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		{"reserved version FF uppercase", "FF-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		{"non-hex version", "zz-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, ok := parseTraceparent(tt.input)
			if ok {
				t.Errorf("expected !ok for %q", tt.input)
			}
		})
	}
}

func TestIsValidHex(t *testing.T) {
	tests := []struct {
		s      string
		length int
		want   bool
	}{
		{"0af7651916cd43dd8448eb211c80319c", 32, true},
		{"b7ad6b7169203331", 16, true},
		{"01", 2, true},
		{"zz", 2, false},
		{"0af765", 32, false},
		{"", 0, true},
		{"GG", 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isValidHex(tt.s, tt.length); got != tt.want {
				t.Errorf("isValidHex(%q, %d) = %v, want %v", tt.s, tt.length, got, tt.want)
			}
		})
	}
}

// createTestSession creates a session via the API and returns the session ID.
func createTestSession(t *testing.T, h http.Handler) string {
	t.Helper()
	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"id":"trace-test-sess","workspace":%q,"policy":"default"}`, ws)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create session: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	return "trace-test-sess"
}

func TestSetTraceContext_Valid(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	h := app.Router()

	sessID := createTestSession(t, h)

	body := `{"trace_id":"0af7651916cd43dd8448eb211c80319c","span_id":"b7ad6b7169203331","trace_flags":"01"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sessions/"+sessID+"/trace-context", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp)
	}
}

func TestSetTraceContext_ValidTraceIDOnly(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	h := app.Router()

	sessID := createTestSession(t, h)

	body := `{"trace_id":"0af7651916cd43dd8448eb211c80319c"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sessions/"+sessID+"/trace-context", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSetTraceContext_InvalidInputs(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	h := app.Router()

	sessID := createTestSession(t, h)

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "missing trace_id",
			body:       `{"span_id":"b7ad6b7169203331"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "trace_id must be 32 hex characters",
		},
		{
			name:       "short trace_id",
			body:       `{"trace_id":"0af765"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "trace_id must be 32 hex characters",
		},
		{
			name:       "non-hex trace_id",
			body:       `{"trace_id":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "trace_id must be 32 hex characters",
		},
		{
			name:       "all-zero trace_id",
			body:       `{"trace_id":"00000000000000000000000000000000"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "trace_id must not be all zeros",
		},
		{
			name:       "short span_id",
			body:       `{"trace_id":"0af7651916cd43dd8448eb211c80319c","span_id":"b7ad6b"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "span_id must be 16 hex characters",
		},
		{
			name:       "all-zero span_id",
			body:       `{"trace_id":"0af7651916cd43dd8448eb211c80319c","span_id":"0000000000000000"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "span_id must not be all zeros",
		},
		{
			name:       "invalid trace_flags",
			body:       `{"trace_id":"0af7651916cd43dd8448eb211c80319c","trace_flags":"zz"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "trace_flags must be 2 hex characters",
		},
		{
			name:       "trace_flags too long",
			body:       `{"trace_id":"0af7651916cd43dd8448eb211c80319c","trace_flags":"0100"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "trace_flags must be 2 hex characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/sessions/"+sessID+"/trace-context", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d: %s", tt.wantStatus, rr.Code, rr.Body.String())
			}
			var resp map[string]any
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if errMsg, ok := resp["error"].(string); !ok || errMsg != tt.wantError {
				t.Errorf("error = %q, want %q", resp["error"], tt.wantError)
			}
		})
	}
}

func TestSetTraceContext_SessionNotFound(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)
	app := newTestApp(t, sessions, store)
	h := app.Router()

	body := `{"trace_id":"0af7651916cd43dd8448eb211c80319c"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sessions/nonexistent/trace-context", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
