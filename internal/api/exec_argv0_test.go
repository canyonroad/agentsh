package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestExec_Argv0_OverridesDollarZero(t *testing.T) {
	st := newSQLiteStore(t)
	store := composite.New(st, st)
	sessions := session.NewManager(10)

	ws := filepath.Join(t.TempDir(), "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	sess, err := sessions.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	app := newTestApp(t, sessions, store)
	h := app.Router()

	body, _ := json.Marshal(map[string]any{
		"command":        "sh",
		"args":           []string{"-c", `printf %s "$0"`},
		"argv0":          "custom0",
		"include_events": "none",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/"+sess.ID+"/exec", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.ExecResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result.ExitCode != 0 {
		t.Fatalf("expected exit_code 0, got %d (stderr=%q)", resp.Result.ExitCode, resp.Result.Stderr)
	}
	if resp.Result.Stdout != "custom0" {
		t.Fatalf("expected stdout custom0, got %q", resp.Result.Stdout)
	}
}
