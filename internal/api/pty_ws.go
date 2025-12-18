package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

type ptyWSStart struct {
	Type       string            `json:"type,omitempty"` // "start"
	Command    string            `json:"command"`
	Args       []string          `json:"args,omitempty"`
	Argv0      string            `json:"argv0,omitempty"`
	WorkingDir string            `json:"working_dir,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Rows       uint16            `json:"rows,omitempty"`
	Cols       uint16            `json:"cols,omitempty"`
}

type ptyWSControl struct {
	Type string `json:"type"` // "resize" | "signal"

	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`

	Name string `json:"name,omitempty"` // signal name, e.g. SIGINT
}

type ptyWSExit struct {
	Type       string `json:"type"` // "exit"
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}

func (a *App) execInSessionPTYWS(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "server not initialized"})
		return
	}
	if !websocket.IsWebSocketUpgrade(r) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "websocket upgrade required"})
		return
	}
	sessionID := chi.URLParam(r, "id")
	if strings.TrimSpace(sessionID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session id is required"})
		return
	}

	up := websocket.Upgrader{
		// Auth middleware already applied; for typical agent harnesses, allow any origin.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(10 * 1024 * 1024)

	// First message must be a JSON start frame (text).
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return
	}
	if mt != websocket.TextMessage {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "first message must be text start"}))
		return
	}
	var start ptyWSStart
	if err := json.Unmarshal(data, &start); err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "invalid start json"}))
		return
	}
	if start.Type != "" && start.Type != "start" {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "expected type=start"}))
		return
	}
	if strings.TrimSpace(start.Command) == "" {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "command is required"}))
		return
	}

	run, httpCode, err := a.startPTY(r.Context(), sessionID, ptyStartParams{
		Command:    start.Command,
		Args:       start.Args,
		Argv0:      start.Argv0,
		WorkingDir: start.WorkingDir,
		Env:        start.Env,
		Rows:       start.Rows,
		Cols:       start.Cols,
	})
	if err != nil {
		_ = httpCode
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": err.Error()}))
		return
	}
	defer run.unlock()

	// Reader loop: stdin bytes (binary) + control (text).
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				_ = run.ps.Signal(syscall.SIGKILL)
				return
			}
			switch mt {
			case websocket.BinaryMessage:
				_, _ = run.ps.Write(msg)
			case websocket.TextMessage:
				var ctl ptyWSControl
				if err := json.Unmarshal(msg, &ctl); err != nil {
					continue
				}
				switch ctl.Type {
				case "resize":
					_ = run.ps.Resize(ctl.Rows, ctl.Cols)
				case "signal":
					switch strings.ToUpper(strings.TrimSpace(ctl.Name)) {
					case "SIGINT":
						_ = run.ps.Signal(syscall.SIGINT)
					case "SIGTERM":
						_ = run.ps.Signal(syscall.SIGTERM)
					case "SIGHUP":
						_ = run.ps.Signal(syscall.SIGHUP)
					case "SIGQUIT":
						_ = run.ps.Signal(syscall.SIGQUIT)
					}
				}
			default:
				// ignore
			}
		}
	}()

	// Writer loop: PTY output bytes as binary frames.
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

	var writeErr error
	for b := range run.ps.Output() {
		appendOut(b)
		if writeErr == nil {
			if werr := conn.WriteMessage(websocket.BinaryMessage, b); werr != nil {
				writeErr = werr
				_ = run.ps.Signal(syscall.SIGKILL)
			}
		}
	}

	exitCode, waitErr := run.ps.Wait()
	a.finishPTY(r.Context(), run, exitCode, run.started, waitErr, out.Bytes(), outTotal, outTrunc)
	if waitErr != nil {
		_ = conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": waitErr.Error()}))
		return
	}

	_ = conn.WriteMessage(websocket.TextMessage, mustJSON(ptyWSExit{
		Type:       "exit",
		ExitCode:   exitCode,
		DurationMs: time.Since(run.started).Milliseconds(),
	}))
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(500*time.Millisecond))
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
