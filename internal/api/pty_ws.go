package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
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

	const (
		wsWriteWait = 10 * time.Second
		wsPongWait  = 60 * time.Second
		wsPingEvery = (wsPongWait * 9) / 10
	)

	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	var writeMu sync.Mutex
	wsWriteMessage := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
		return conn.WriteMessage(messageType, data)
	}
	wsWriteControl := func(messageType int, data []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteControl(messageType, data, time.Now().Add(wsWriteWait))
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(wsPingEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := wsWriteControl(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	// First message must be a JSON start frame (text).
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Now().Add(wsPongWait))
	if mt != websocket.TextMessage {
		_ = wsWriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "first message must be text start"}))
		return
	}
	var start ptyWSStart
	if err := json.Unmarshal(data, &start); err != nil {
		_ = wsWriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "invalid start json"}))
		return
	}
	if start.Type != "" && start.Type != "start" {
		_ = wsWriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "expected type=start"}))
		return
	}
	if strings.TrimSpace(start.Command) == "" {
		_ = wsWriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": "command is required"}))
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
		_ = wsWriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "code": httpCode, "message": err.Error()}))
		return
	}
	defer run.unlock()

	// Reader loop: stdin bytes (binary) + control (text).
	go func() {
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				_ = run.ps.Signal(syscall.SIGKILL)
				return
			}
			conn.SetReadDeadline(time.Now().Add(wsPongWait))
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
			if werr := wsWriteMessage(websocket.BinaryMessage, b); werr != nil {
				writeErr = werr
				_ = run.ps.Signal(syscall.SIGKILL)
			}
		}
	}

	exitCode, waitErr := run.ps.Wait()
	a.finishPTY(r.Context(), run, exitCode, run.started, waitErr, out.Bytes(), outTotal, outTrunc)
	if waitErr != nil {
		_ = wsWriteMessage(websocket.TextMessage, mustJSON(map[string]any{"type": "error", "message": waitErr.Error()}))
		return
	}

	_ = wsWriteMessage(websocket.TextMessage, mustJSON(ptyWSExit{
		Type:       "exit",
		ExitCode:   exitCode,
		DurationMs: time.Since(run.started).Milliseconds(),
	}))
	_ = wsWriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
