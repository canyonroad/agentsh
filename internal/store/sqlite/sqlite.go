package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA foreign_keys=ON;`,
		`CREATE TABLE IF NOT EXISTS events (
			event_id TEXT PRIMARY KEY,
			ts_unix_ns INTEGER NOT NULL,
			session_id TEXT NOT NULL,
			command_id TEXT,
			type TEXT NOT NULL,
			pid INTEGER,
			policy_decision TEXT,
			effective_decision TEXT,
			policy_rule TEXT,
			path TEXT,
			domain TEXT,
			remote TEXT,
			operation TEXT,
			payload_json TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts_unix_ns);`,
		`CREATE INDEX IF NOT EXISTS idx_events_command_ts ON events(command_id, ts_unix_ns);`,
		`CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type, ts_unix_ns);`,
		`CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);`,
		`CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);`,
		`CREATE TABLE IF NOT EXISTS command_outputs (
			command_id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			stdout BLOB,
			stderr BLOB,
			stdout_total_bytes INTEGER NOT NULL,
			stderr_total_bytes INTEGER NOT NULL,
			stdout_truncated INTEGER NOT NULL,
			stderr_truncated INTEGER NOT NULL,
			created_ts_unix_ns INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS mcp_tools (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			tool_hash TEXT NOT NULL,
			description TEXT,
			first_seen_ns INTEGER NOT NULL,
			last_seen_ns INTEGER NOT NULL,
			pinned INTEGER DEFAULT 1,
			detection_count INTEGER DEFAULT 0,
			max_severity TEXT,
			UNIQUE(server_id, tool_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_mcp_tools_server ON mcp_tools(server_id);`,
		`CREATE INDEX IF NOT EXISTS idx_mcp_tools_severity ON mcp_tools(max_severity);`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlite migrate: %w", err)
		}
	}
	return nil
}

func (s *Store) AppendEvent(ctx context.Context, ev types.Event) error {
	if ev.ID == "" {
		return fmt.Errorf("event missing id")
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	var policyDecision, effectiveDecision, policyRule string
	if ev.Policy != nil {
		policyDecision = string(ev.Policy.Decision)
		effectiveDecision = string(ev.Policy.EffectiveDecision)
		policyRule = ev.Policy.Rule
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO events(
			event_id, ts_unix_ns, session_id, command_id, type, pid,
			policy_decision, effective_decision, policy_rule,
			path, domain, remote, operation, payload_json
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?);`,
		ev.ID,
		ev.Timestamp.UTC().UnixNano(),
		ev.SessionID,
		nullable(ev.CommandID),
		ev.Type,
		nullableInt(ev.PID),
		nullable(policyDecision),
		nullable(effectiveDecision),
		nullable(policyRule),
		nullable(ev.Path),
		nullable(ev.Domain),
		nullable(ev.Remote),
		nullable(ev.Operation),
		string(b),
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

func (s *Store) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	where := []string{"1=1"}
	var args []any

	if q.SessionID != "" {
		where = append(where, "session_id = ?")
		args = append(args, q.SessionID)
	}
	if q.CommandID != "" {
		where = append(where, "command_id = ?")
		args = append(args, q.CommandID)
	}
	if len(q.Types) > 0 {
		place := make([]string, 0, len(q.Types))
		for _, t := range q.Types {
			place = append(place, "?")
			args = append(args, t)
		}
		where = append(where, "type IN ("+strings.Join(place, ",")+")")
	}
	if q.Since != nil {
		where = append(where, "ts_unix_ns >= ?")
		args = append(args, q.Since.UTC().UnixNano())
	}
	if q.Until != nil {
		where = append(where, "ts_unix_ns <= ?")
		args = append(args, q.Until.UTC().UnixNano())
	}
	if q.Decision != nil {
		where = append(where, "policy_decision = ?")
		args = append(args, string(*q.Decision))
	}
	if q.PathLike != "" {
		where = append(where, "path LIKE ?")
		args = append(args, q.PathLike)
	}
	if q.DomainLike != "" {
		where = append(where, "domain LIKE ?")
		args = append(args, q.DomainLike)
	}
	if q.TextLike != "" {
		where = append(where, "payload_json LIKE ?")
		args = append(args, q.TextLike)
	}

	order := "DESC"
	if q.Asc {
		order = "ASC"
	}
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT payload_json FROM events WHERE `+strings.Join(where, " AND ")+` ORDER BY ts_unix_ns `+order+` LIMIT ? OFFSET ?`,
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var out []types.Event
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		var ev types.Event
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			return nil, fmt.Errorf("unmarshal event: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query events rows: %w", err)
	}
	return out, nil
}

func (s *Store) SaveOutput(ctx context.Context, sessionID, commandID string, stdout, stderr []byte, stdoutTotal, stderrTotal int64, stdoutTrunc, stderrTrunc bool) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO command_outputs(
			command_id, session_id, stdout, stderr,
			stdout_total_bytes, stderr_total_bytes,
			stdout_truncated, stderr_truncated,
			created_ts_unix_ns
		) VALUES(?,?,?,?,?,?,?,?,?);`,
		commandID,
		sessionID,
		stdout,
		stderr,
		stdoutTotal,
		stderrTotal,
		boolToInt(stdoutTrunc),
		boolToInt(stderrTrunc),
		time.Now().UTC().UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("save output: %w", err)
	}
	return nil
}

func (s *Store) ReadOutputChunk(ctx context.Context, commandID string, stream string, offset, limit int64) ([]byte, int64, bool, error) {
	if limit <= 0 || limit > 10*1024*1024 {
		limit = 64 * 1024
	}
	if offset < 0 {
		offset = 0
	}
	stream = strings.ToLower(stream)
	if stream != "stdout" && stream != "stderr" {
		stream = "stdout"
	}

	var data []byte
	var total int64
	var truncatedInt int

	row := s.db.QueryRowContext(ctx, `SELECT `+stream+`, `+stream+`_total_bytes, `+stream+`_truncated FROM command_outputs WHERE command_id = ?`, commandID)
	if err := row.Scan(&data, &total, &truncatedInt); err != nil {
		if err == sql.ErrNoRows {
			return nil, 0, false, fmt.Errorf("output not found")
		}
		return nil, 0, false, fmt.Errorf("read output: %w", err)
	}

	if offset >= int64(len(data)) {
		return []byte{}, total, truncatedInt != 0, nil
	}
	end := offset + limit
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return data[offset:end], total, truncatedInt != 0, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(i int) any {
	if i == 0 {
		return nil
	}
	return i
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
