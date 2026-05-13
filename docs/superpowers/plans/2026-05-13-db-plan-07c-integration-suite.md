# DB Plan 07c Integration Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a CI-required real Postgres integration suite for DB Plan 07 and update the DB access docs so `policies.db.unavoidability: enforce` is the high-assurance recommendation for declared Phase 1 Postgres services.

**Architecture:** The suite runs under the existing `integration` build tag, starts Postgres and AgentSH server containers on the same Docker bridge network, creates an AgentSH session with DB unavoidability enforce mode, and executes a small `pgx` helper binary through the AgentSH exec API so the proxy listener can authenticate the owning SessionID through ptrace. Small production changes expose the per-session DB proxy socket in API session snapshots and publish normalized DB statement events through the existing composite store and event broker.

**Tech Stack:** Go, `testcontainers-go`, Docker, `postgres:16-alpine`, `github.com/jackc/pgx/v5`, AgentSH REST client, existing `internal/db/proxy/postgres` proxy, existing `integration` build tag.

---

## File Structure

- Modify: `pkg/types/sessions.go` - add `db_proxy_socket_dir` to the public session API response so integration clients can discover per-session DB proxy sockets without duplicating internal state-dir layout.
- Modify: `internal/session/manager.go` - include the existing `Session.dbProxySocketDir` in `Snapshot()`.
- Modify: `internal/session/manager_test.go` - add a unit test for the snapshot field.
- Modify: `internal/api/db_lifecycle_sink.go` - map `dbevents.DBEvent` into `types.Event` and publish statement, cancel, and COPY events through the API/store/broker path.
- Modify: `internal/api/db_lifecycle_sink_test.go` - add mapping and broker-publication tests for DB statement events.
- Create: `internal/integration/db07cclient/main.go` - Linux-container helper binary that uses `pgx` to connect through either the proxy Unix socket or direct TCP and exercises scalar, exec, tx-deny, cancel, COPY TO, and COPY FROM modes.
- Create: `internal/integration/db_postgres_07c_test.go` - Docker-backed real Postgres integration suite with AgentSH server container, DB policy/config writers, session event polling, and tests for SQL flows, cancel/COPY, direct TCP bypass, and listener auth failure.
- Modify: `docs/superpowers/specs/2026-05-13-db-plan-07-split-unavoidability-design.md` - record 07c as the CI closeout gate for Plan 07.
- Modify: `docs/agentsh-db-access-spec.md` - update Phase 1 operator guidance for `policies.db.unavoidability: enforce` with scope caveats.

## Task 1: Expose Session DB Proxy Socket In API Snapshots

**Files:**
- Modify: `pkg/types/sessions.go`
- Modify: `internal/session/manager.go`
- Modify: `internal/session/manager_test.go`

- [ ] **Step 1: Write the failing snapshot test**

Append this test near the existing DB proxy tests in `internal/session/manager_test.go`:

```go
func TestSessionSnapshotIncludesDBProxySocketDir(t *testing.T) {
	mgr := NewManager(5)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	socketDir := filepath.Join(t.TempDir(), "db-services")
	s.SetDBProxy(socketDir, func() error { return nil })

	snap := s.Snapshot()
	if snap.DBProxySocketDir != socketDir {
		t.Fatalf("Snapshot().DBProxySocketDir = %q, want %q", snap.DBProxySocketDir, socketDir)
	}
}
```

- [ ] **Step 2: Run the focused test and confirm the red state**

Run:

```bash
go test ./internal/session -run TestSessionSnapshotIncludesDBProxySocketDir -count=1
```

Expected: FAIL at compile time because `types.Session` has no `DBProxySocketDir` field.

- [ ] **Step 3: Add the API field**

In `pkg/types/sessions.go`, add the field after `LLMProxyURL`:

```go
	DBProxySocketDir string `json:"db_proxy_socket_dir,omitempty"`
```

The surrounding `Session` struct should contain:

```go
	ProxyURL         string       `json:"proxy_url,omitempty"`
	LLMProxyURL      string       `json:"llm_proxy_url,omitempty"`
	DBProxySocketDir string       `json:"db_proxy_socket_dir,omitempty"`
	TOTPSecret       string       `json:"-"` // Hidden from JSON/API, used for TOTP approval mode
```

- [ ] **Step 4: Populate the field in snapshots**

In `internal/session/manager.go`, add `DBProxySocketDir` to the `types.Session` literal returned by `(*Session).Snapshot()`:

```go
		ProxyURL:         s.proxyURL,
		LLMProxyURL:      s.llmProxyURL,
		DBProxySocketDir: s.dbProxySocketDir,
		TOTPSecret:       s.TOTPSecret,
```

- [ ] **Step 5: Run the focused test and commit**

Run:

```bash
go test ./internal/session -run TestSessionSnapshotIncludesDBProxySocketDir -count=1
```

Expected: PASS.

Commit:

```bash
git add pkg/types/sessions.go internal/session/manager.go internal/session/manager_test.go
git commit -m "api: expose session db proxy socket"
```

## Task 2: Publish Normalized DB Statement Events Through API Sink

**Files:**
- Modify: `internal/api/db_lifecycle_sink.go`
- Modify: `internal/api/db_lifecycle_sink_test.go`

- [ ] **Step 1: Add failing mapping and publication tests**

Update `internal/api/db_lifecycle_sink_test.go` imports to include `context` and the app event broker package:

```go
import (
	"context"
	"testing"
	"time"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	appevents "github.com/agentsh/agentsh/internal/events"
)
```

Append these tests:

```go
func TestDBStatementToEventMapsNormalizedFields(t *testing.T) {
	rowsReturned := int64(3)
	rowsAffected := int64(0)
	ts := time.Unix(456, 0).UTC()

	ev := dbStatementToEvent(dbevents.DBEvent{
		EventID:            "db-evt-1",
		SessionID:          "sess-db",
		CommandID:          "cmd-db",
		Timestamp:          ts,
		DBService:          "appdb",
		DBFamily:           "postgres",
		DBDialect:          "postgres",
		DBUser:             "app",
		Database:           "app",
		ApplicationName:    "db07c",
		ClientIdentity:     "sess-db",
		OperationGroup:     "bulk_export",
		OperationGroupID:   5,
		OperationSubtype:   "copy_to",
		RawVerb:            "COPY",
		ObjectResolution:   "syntactic",
		StatementDigest:    "sha256:abc",
		StatementText:      "COPY (SELECT note FROM db07c_copy) TO STDOUT WITH CSV",
		StatementRedaction: dbevents.RedactionNone,
		Decision: dbevents.EventDecision{
			Verb:                "allow",
			RuleKind:            "statement",
			RuleName:            "allow-copy",
			MatchingEffectIndex: 0,
		},
		Result: dbevents.EventResult{
			RowsReturned: &rowsReturned,
			RowsAffected: &rowsAffected,
			BytesOut:     11,
			LatencyMs:    7,
		},
		TxContext: dbevents.EventTxContext{DenyAction: "none"},
	})

	if ev.ID != "db-evt-1" || ev.Timestamp != ts || ev.Type != "db_statement" {
		t.Fatalf("event identity = %+v", ev)
	}
	if ev.SessionID != "sess-db" || ev.CommandID != "cmd-db" || ev.Operation != "bulk_export" {
		t.Fatalf("event session/operation = %+v", ev)
	}
	if ev.Fields["db_service"] != "appdb" || ev.Fields["operation_subtype"] != "copy_to" {
		t.Fatalf("fields missing service/subtype: %+v", ev.Fields)
	}
	if ev.Fields["statement_text"] != "COPY (SELECT note FROM db07c_copy) TO STDOUT WITH CSV" {
		t.Fatalf("statement_text = %#v", ev.Fields["statement_text"])
	}
	decision, ok := ev.Fields["decision"].(map[string]any)
	if !ok || decision["verb"] != "allow" || decision["rule_name"] != "allow-copy" {
		t.Fatalf("decision field = %#v", ev.Fields["decision"])
	}
	result, ok := ev.Fields["result"].(map[string]any)
	if !ok || result["bytes_out"] != float64(11) || result["latency_ms"] != float64(7) {
		t.Fatalf("result field = %#v", ev.Fields["result"])
	}
	txContext, ok := ev.Fields["tx_context"].(map[string]any)
	if !ok || txContext["deny_action"] != "none" {
		t.Fatalf("tx_context field = %#v", ev.Fields["tx_context"])
	}
}

func TestDBAuditSinkEmitStatementPublishesToBroker(t *testing.T) {
	broker := appevents.NewBroker()
	ch := broker.Subscribe("sess-db", 1)
	defer broker.Unsubscribe("sess-db", ch)

	sink := dbAuditSink{broker: broker}
	err := sink.EmitStatement(context.Background(), dbevents.DBEvent{
		EventID:        "db-evt-pub",
		SessionID:      "sess-db",
		CommandID:      "cmd-db",
		Timestamp:      time.Unix(789, 0).UTC(),
		DBService:      "appdb",
		DBFamily:       "postgres",
		DBDialect:      "postgres",
		OperationGroup: "session",
		Decision:       dbevents.EventDecision{Verb: "allow", RuleKind: "cancel", RuleName: "allow-app-cancel"},
		Result:         dbevents.EventResult{ErrorCode: "57014"},
	})
	if err != nil {
		t.Fatalf("EmitStatement: %v", err)
	}

	select {
	case got := <-ch:
		if got.Type != "db_statement" || got.ID != "db-evt-pub" || got.SessionID != "sess-db" {
			t.Fatalf("published event = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("EmitStatement did not publish db_statement")
	}
}
```

- [ ] **Step 2: Run the focused API tests and confirm the red state**

Run:

```bash
go test ./internal/api -run 'TestDBStatementToEvent|TestDBAuditSinkEmitStatement' -count=1
```

Expected: FAIL at compile time because `dbStatementToEvent` is not defined and `EmitStatement` does not publish.

- [ ] **Step 3: Implement statement event mapping and publication**

Replace the `EmitStatement` no-op in `internal/api/db_lifecycle_sink.go` and add the helper functions shown here. Keep the existing lifecycle functions unchanged.

```go
package api

import (
	"context"
	"encoding/json"
	"strings"

	dbevents "github.com/agentsh/agentsh/internal/db/events"
	appevents "github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/pkg/types"
)
```

```go
func (s dbAuditSink) EmitStatement(ctx context.Context, ev dbevents.DBEvent) error {
	typesEv := dbStatementToEvent(ev)
	if s.store != nil {
		if err := s.store.AppendEvent(ctx, typesEv); err != nil {
			return err
		}
	}
	if s.broker != nil {
		s.broker.Publish(typesEv)
	}
	return nil
}

func dbStatementToEvent(ev dbevents.DBEvent) types.Event {
	fields := map[string]any{
		"db_service":          ev.DBService,
		"db_family":           ev.DBFamily,
		"db_dialect":          ev.DBDialect,
		"db_user":             ev.DBUser,
		"database":            ev.Database,
		"application_name":    ev.ApplicationName,
		"client_identity":     ev.ClientIdentity,
		"operation_group":     ev.OperationGroup,
		"operation_group_id":  ev.OperationGroupID,
		"operation_subtype":   ev.OperationSubtype,
		"raw_verb":            ev.RawVerb,
		"object_resolution":   ev.ObjectResolution,
		"statement_digest":    ev.StatementDigest,
		"statement_text":      ev.StatementText,
		"parser_backend":      ev.ParserBackend.String(),
		"statement_redaction": dbEventField(ev.StatementRedaction),
		"tls":                 dbEventField(ev.TLS),
		"decision":            dbEventField(ev.Decision),
		"result":              dbEventField(ev.Result),
		"tx_context":          dbEventField(ev.TxContext),
	}
	if len(ev.Effects) > 0 {
		fields["effects"] = dbEventField(ev.Effects)
	}
	if ev.Predicates != (dbevents.EventPredicates{}) {
		fields["predicates"] = dbEventField(ev.Predicates)
	}

	return types.Event{
		ID:        ev.EventID,
		Timestamp: ev.Timestamp,
		Type:      "db_statement",
		SessionID: ev.SessionID,
		CommandID: ev.CommandID,
		Operation: ev.OperationGroup,
		Fields:    fields,
	}
}

func dbEventField(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}
```

- [ ] **Step 4: Run focused API tests and commit**

Run:

```bash
go test ./internal/api -run 'TestDBStatementToEvent|TestDBAuditSinkEmitStatement|TestDBLifecycleToEvent' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/api/db_lifecycle_sink.go internal/api/db_lifecycle_sink_test.go
git commit -m "api: publish db statement events"
```

## Task 3: Add The PGX Integration Helper Binary

**Files:**
- Create: `internal/integration/db07cclient/main.go`

- [ ] **Step 1: Create the helper binary source**

Create `internal/integration/db07cclient/main.go` with this implementation:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type output struct {
	OK             bool   `json:"ok"`
	Mode           string `json:"mode"`
	Scalar         string `json:"scalar,omitempty"`
	RowsAffected   int64  `json:"rows_affected,omitempty"`
	BytesIn        int64  `json:"bytes_in,omitempty"`
	BytesOut       int64  `json:"bytes_out,omitempty"`
	CommandTag     string `json:"command_tag,omitempty"`
	SQLState       string `json:"sql_state,omitempty"`
	Error          string `json:"error,omitempty"`
	ConnectionOpen bool   `json:"connection_open,omitempty"`
}

func main() {
	var (
		dsn      = flag.String("dsn", "", "direct PostgreSQL DSN")
		socket   = flag.String("socket", "", "AgentSH DB proxy Unix socket path")
		mode     = flag.String("mode", "scalar", "scalar, exec, tx-deny, cancel, copy-to, or copy-from")
		sqlText  = flag.String("sql", "select 1", "SQL statement")
		data     = flag.String("data", "", "COPY FROM STDIN payload")
		user     = flag.String("user", "app", "startup user for socket mode")
		password = flag.String("password", "secret", "startup password for socket mode")
		database = flag.String("database", "app", "startup database for socket mode")
		timeout  = flag.Duration("timeout", 5*time.Second, "operation timeout")
		simple   = flag.Bool("simple", false, "use PostgreSQL simple query protocol")
	)
	flag.Parse()

	if (*dsn == "") == (*socket == "") {
		write(output{OK: false, Mode: *mode, Error: "set exactly one of -dsn or -socket"})
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cfg, err := config(*dsn, *socket, *user, *password, *database, *simple)
	if err != nil {
		write(output{OK: false, Mode: *mode, Error: err.Error()})
		os.Exit(2)
	}

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		write(output{OK: false, Mode: *mode, SQLState: sqlState(err), Error: err.Error()})
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	out, err := run(ctx, conn, *mode, *sqlText, *data)
	out.Mode = *mode
	if err != nil {
		out.OK = false
		out.SQLState = sqlState(err)
		out.Error = err.Error()
		write(out)
		os.Exit(1)
	}
	out.OK = true
	write(out)
}

func config(dsn, socket, user, password, database string, simple bool) (*pgx.ConnConfig, error) {
	if dsn == "" {
		u := &url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(user, password),
			Host:   "localhost",
			Path:   database,
		}
		q := u.Query()
		q.Set("sslmode", "disable")
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if socket != "" {
		socketPath := socket
		cfg.Config.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}
	}
	if simple {
		cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	}
	return cfg, nil
}

func run(ctx context.Context, conn *pgx.Conn, mode, sqlText, data string) (output, error) {
	switch mode {
	case "scalar":
		var scalar string
		if err := conn.QueryRow(ctx, sqlText).Scan(&scalar); err != nil {
			return output{}, err
		}
		return output{Scalar: scalar}, nil
	case "exec":
		tag, err := conn.Exec(ctx, sqlText)
		if err != nil {
			return output{}, err
		}
		return output{RowsAffected: tag.RowsAffected(), CommandTag: tag.String()}, nil
	case "tx-deny":
		tx, err := conn.Begin(ctx)
		if err != nil {
			return output{}, err
		}
		_, execErr := tx.Exec(ctx, sqlText)
		_ = tx.Rollback(context.Background())
		if execErr == nil {
			return output{ConnectionOpen: ping(context.Background(), conn)}, errors.New("tx-deny statement unexpectedly succeeded")
		}
		return output{SQLState: sqlState(execErr), Error: execErr.Error(), ConnectionOpen: ping(context.Background(), conn)}, nil
	case "cancel":
		cancelCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		defer cancel()
		_, err := conn.Exec(cancelCtx, sqlText)
		if err == nil {
			return output{}, errors.New("cancel query unexpectedly completed")
		}
		state := sqlState(err)
		if state != "57014" && !strings.Contains(strings.ToLower(err.Error()), "cancel") && !errors.Is(err, context.DeadlineExceeded) {
			return output{SQLState: state, Error: err.Error()}, err
		}
		return output{SQLState: state, Error: err.Error(), ConnectionOpen: ping(context.Background(), conn)}, nil
	case "copy-to":
		var buf bytes.Buffer
		tag, err := conn.PgConn().CopyTo(ctx, &buf, sqlText)
		if err != nil {
			return output{}, err
		}
		return output{BytesOut: int64(buf.Len()), CommandTag: tag.String()}, nil
	case "copy-from":
		tag, err := conn.PgConn().CopyFrom(ctx, strings.NewReader(data), sqlText)
		if err != nil {
			return output{}, err
		}
		return output{BytesIn: int64(len(data)), CommandTag: tag.String()}, nil
	default:
		return output{}, fmt.Errorf("unknown mode %q", mode)
	}
}

func ping(ctx context.Context, conn *pgx.Conn) bool {
	pingCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return conn.Ping(pingCtx) == nil
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func write(out output) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}
```

- [ ] **Step 2: Build the helper for the local host and Linux container targets**

Run:

```bash
go build ./internal/integration/db07cclient
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$(mktemp -d)/db07c-client" ./internal/integration/db07cclient
```

Expected: both builds pass.

- [ ] **Step 3: Commit the helper**

Commit:

```bash
git add internal/integration/db07cclient/main.go
git commit -m "test: add db 07c pgx client helper"
```

## Task 4: Add Real Postgres Harness And Core 07c Tests

**Files:**
- Create: `internal/integration/db_postgres_07c_test.go`

- [ ] **Step 1: Create the integration test file with harness and core tests**

Create `internal/integration/db_postgres_07c_test.go` with this structure and code. Keep the build tag exactly as shown so normal unit tests and Windows builds do not try to start Docker.

```go
//go:build integration && linux

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/docker/docker/api/types/container"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

type db07cEnv struct {
	client             *client.Client
	server             testcontainers.Container
	hostDSN            string
	containerDSN       string
	postgresContainer  testcontainers.Container
	networkName        string
	cleanup            func()
}

type db07cClientOutput struct {
	OK             bool   `json:"ok"`
	Mode           string `json:"mode"`
	Scalar         string `json:"scalar"`
	RowsAffected   int64  `json:"rows_affected"`
	BytesIn        int64  `json:"bytes_in"`
	BytesOut       int64  `json:"bytes_out"`
	CommandTag     string `json:"command_tag"`
	SQLState       string `json:"sql_state"`
	Error          string `json:"error"`
	ConnectionOpen bool   `json:"connection_open"`
}

func TestDB07CRealPostgresProxySQLAndUnavoidability(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	allow := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select '07c-ok'", "-simple")
	if allow.Scalar != "07c-ok" {
		t.Fatalf("07c real Postgres proxy did not return rows through appdb: %+v", allow)
	}

	extended := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from db07c_guard where id = 1")
	if extended.Scalar != "seed" {
		t.Fatalf("07c extended query through appdb returned %+v", extended)
	}

	deny := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "tx-deny", "-sql", "insert into db07c_guard(id, note) values (2, 'denied')")
	if deny.SQLState == "" && deny.Error == "" {
		t.Fatalf("07c deny did not report SQLSTATE or error: %+v", deny)
	}
	assertGuardCount07C(t, ctx, env.hostDSN, 1)

	bypass := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-dsn", env.containerDSN, "-mode", "scalar", "-sql", "select 'bypass'")
	if bypass.OK {
		t.Fatalf("07c direct TCP bypass unexpectedly succeeded: %+v", bypass)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		return ev.Type == "db_bypass_attempt" && ev.Fields["db_service"] == "appdb"
	}, "db_bypass_attempt")
}

func TestDB07CRejectsListenerAccessOutsideOwningSession(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	exitCode, reader, err := env.server.Exec(ctx, []string{"/usr/local/bin/db07c-client", "-socket", socket, "-mode", "scalar", "-sql", "select 'outside'"})
	if err != nil {
		t.Fatalf("server Exec db07c-client: %v", err)
	}
	out, _ := io.ReadAll(reader)
	if exitCode == 0 {
		t.Fatalf("07c cross-session listener access was accepted: %s", string(out))
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		return ev.Type == "db_listener_auth_fail" && ev.Fields["db_service"] == "appdb"
	}, "db_listener_auth_fail")
}

func startDB07CEnvironment(t *testing.T, ctx context.Context) db07cEnv {
	t.Helper()

	netw, err := tcnetwork.New(ctx, tcnetwork.WithAttachable(), tcnetwork.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("07c create Docker network: %v", err)
	}

	cleanup := func() {
		_ = netw.Remove(context.Background())
	}
	t.Cleanup(cleanup)

	pgReq := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "app",
			"POSTGRES_PASSWORD": "secret",
			"POSTGRES_DB":       "app",
		},
		Networks:       []string{netw.Name},
		NetworkAliases: map[string][]string{netw.Name: []string{"pg07c"}},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: pgReq, Started: true})
	if err != nil {
		t.Fatalf("07c start postgres container: %v", err)
	}

	host, err := pg.Host(ctx)
	if err != nil {
		t.Fatalf("07c postgres host: %v", err)
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("07c postgres mapped port: %v", err)
	}
	hostDSN := fmt.Sprintf("postgres://app:secret@%s:%s/app?sslmode=disable", host, port.Port())
	containerDSN := "postgres://app:secret@pg07c:5432/app?sslmode=disable"

	temp := t.TempDir()
	agentshBin := buildAgentshBinary(t)
	clientBin := buildDB07CClientBinary(t)
	policiesDir := filepath.Join(temp, "policies")
	mustMkdir(t, policiesDir)
	writeFile(t, filepath.Join(policiesDir, "default.yaml"), db07cPolicyYAML())
	writeFile(t, filepath.Join(temp, "keys.yaml"), testAPIKeysYAML)
	writeFile(t, filepath.Join(temp, "config.yaml"), db07cConfigYAML())
	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, server, serverCleanup := startDB07CServerContainer(t, ctx, netw.Name, agentshBin, clientBin, filepath.Join(temp, "config.yaml"), policiesDir, workspace)
	env := db07cEnv{
		client:            client.New(endpoint, "test-key"),
		server:            server,
		hostDSN:           hostDSN,
		containerDSN:      containerDSN,
		postgresContainer: pg,
		networkName:       netw.Name,
	}
	env.cleanup = func() {
		serverCleanup()
		_ = pg.Terminate(context.Background())
		_ = netw.Remove(context.Background())
	}
	return env
}

func buildDB07CClientBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "db07c-client")
	repoRoot := repoRoot07C(t)
	cmd := exec.Command("go", "build", "-o", out, "./internal/integration/db07cclient")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build db07c-client: %v", err)
	}
	return out
}

func repoRoot07C(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatalf("go.mod not found when walking up from %s", wd)
		}
		wd = next
	}
}

func startDB07CServerContainer(t *testing.T, ctx context.Context, networkName, agentshBin, dbClientBin, configPath, policiesDir, workspace string) (string, testcontainers.Container, func()) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "debian:bookworm-slim",
		ExposedPorts: []string{"18080/tcp"},
		Cmd:          []string{"/usr/local/bin/agentsh", "server", "--config", "/config.yaml"},
		Mounts: []testcontainers.ContainerMount{
			testcontainers.BindMount(agentshBin, "/usr/local/bin/agentsh"),
			testcontainers.BindMount(dbClientBin, "/usr/local/bin/db07c-client"),
			testcontainers.BindMount(configPath, "/config.yaml"),
			testcontainers.BindMount(filepath.Join(filepath.Dir(configPath), "keys.yaml"), "/keys.yaml"),
			testcontainers.BindMount(policiesDir, "/policies"),
			testcontainers.BindMount(workspace, "/workspace"),
		},
		Privileged:      true,
		CapAdd:          []string{"SYS_ADMIN", "SYS_PTRACE"},
		Networks:        []string{networkName},
		NetworkAliases:  map[string][]string{networkName: []string{"agentsh07c"}},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"apparmor:unconfined", "seccomp:unconfined"}
			if _, err := os.Stat("/dev/fuse"); err == nil {
				hc.Devices = append(hc.Devices, container.DeviceMapping{
					PathOnHost:        "/dev/fuse",
					PathInContainer:   "/dev/fuse",
					CgroupPermissions: "rwm",
				})
			}
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("18080/tcp").
			WithStartupTimeout(60 * time.Second).
			WithStatusCodeMatcher(func(code int) bool { return code == http.StatusOK || code == http.StatusNotFound }),
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		if ctr != nil {
			if logs, logErr := ctr.Logs(ctx); logErr == nil {
				defer logs.Close()
				b, _ := io.ReadAll(logs)
				t.Logf("07c AgentSH logs:\n%s", string(b))
			}
		}
		t.Fatalf("07c start AgentSH container: %v", err)
	}
	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("07c AgentSH host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "18080/tcp")
	if err != nil {
		t.Fatalf("07c AgentSH mapped port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())
	return endpoint, ctr, func() { _ = ctr.Terminate(context.Background()) }
}

func db07cConfigYAML() string {
	return `
server:
  http:
    addr: "0.0.0.0:18080"
auth:
  type: "api_key"
  api_key:
    keys_file: "/keys.yaml"
    header_name: "X-API-Key"
logging:
  level: "info"
  format: "text"
  output: "stdout"
audit:
  enabled: false
  storage:
    sqlite_path: "/sessions/events.db"
sessions:
  base_dir: "/sessions"
sandbox:
  fuse:
    enabled: false
  network:
    enabled: false
  unix_sockets:
    enabled: false
  seccomp:
    execve:
      enabled: false
  ptrace:
    enabled: true
    attach_mode: "children"
    trace:
      execve: true
      file: true
      network: true
      signal: true
    performance:
      seccomp_prefilter: true
      max_tracees: 500
      max_hold_ms: 5000
policies:
  dir: "/policies"
  default: "default"
approvals:
  enabled: false
metrics:
  enabled: false
health:
  path: "/health"
`
}

func db07cPolicyYAML() string {
	return `
version: 1
name: default
description: db 07c real postgres integration policy
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: pg07c:5432
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-app-connect
    db_service: appdb
    db_user: ["app"]
    database: app
    decision: allow
  - name: allow-app-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
database_rules:
  - name: deny-mutations
    db_service: appdb
    operations: [write, modify, delete]
    decision: deny
    deny_mode_in_tx: terminate
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
  - name: allow-session
    db_service: appdb
    operations: [session]
    decision: allow
  - name: allow-transaction
    db_service: appdb
    operations: [transaction]
    decision: allow
  - name: allow-copy
    db_service: appdb
    operations: [bulk_export, bulk_load]
    decision: allow
policies:
  db:
    unavoidability: enforce
command_rules:
  - name: allow-db07c-client
    commands: ["*"]
    decision: allow
network_rules:
  - name: allow-network
    domains: ["**"]
    decision: allow
resource_limits:
  command_timeout: 30s
  session_timeout: 1h
  idle_timeout: 30m
`
}

func seedDB07C(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("07c connect host Postgres: %v", err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `
drop table if exists db07c_guard;
create table db07c_guard(id integer primary key, note text not null);
insert into db07c_guard(id, note) values (1, 'seed');
drop table if exists db07c_copy;
create table db07c_copy(id serial primary key, note text not null);
insert into db07c_copy(note) values ('copy-seed');
`)
	if err != nil {
		t.Fatalf("07c seed Postgres: %v", err)
	}
}

func createDB07CSession(t *testing.T, ctx context.Context, cli *client.Client) types.Session {
	t.Helper()
	sess, err := cli.CreateSession(ctx, "/workspace", "default")
	if err != nil {
		t.Fatalf("07c CreateSession: %v", err)
	}
	if sess.DBProxySocketDir == "" {
		t.Fatal("07c session missing db_proxy_socket_dir")
	}
	return sess
}

func execDB07CClient(t *testing.T, ctx context.Context, cli *client.Client, sessionID string, args ...string) db07cClientOutput {
	t.Helper()
	out := execDB07CClientAllowFailure(t, ctx, cli, sessionID, args...)
	if !out.OK {
		t.Fatalf("07c db07c-client failed: %+v", out)
	}
	return out
}

func execDB07CClientAllowFailure(t *testing.T, ctx context.Context, cli *client.Client, sessionID string, args ...string) db07cClientOutput {
	t.Helper()
	resp, err := cli.Exec(ctx, sessionID, types.ExecRequest{
		Command:       "/usr/local/bin/db07c-client",
		Args:          args,
		IncludeEvents: "all",
	})
	if err != nil {
		t.Fatalf("07c Exec db07c-client: %v", err)
	}
	var out db07cClientOutput
	if err := json.Unmarshal([]byte(resp.Result.Stdout), &out); err != nil {
		t.Fatalf("07c decode db07c-client stdout %q stderr %q exit %d: %v", resp.Result.Stdout, resp.Result.Stderr, resp.Result.ExitCode, err)
	}
	if resp.Result.ExitCode == 0 && !out.OK {
		t.Fatalf("07c helper exit 0 with ok=false: %+v", out)
	}
	return out
}

func assertGuardCount07C(t *testing.T, ctx context.Context, dsn string, want int) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("07c connect host Postgres: %v", err)
	}
	defer conn.Close(ctx)
	var got int
	if err := conn.QueryRow(ctx, "select count(*) from db07c_guard").Scan(&got); err != nil {
		t.Fatalf("07c count guard rows: %v", err)
	}
	if got != want {
		t.Fatalf("07c deny reached upstream: marker table count = %d, want %d", got, want)
	}
}

func waitForSessionEvent07C(t *testing.T, ctx context.Context, cli *client.Client, sessionID string, pred func(types.Event) bool, label string) types.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var observed []types.Event
	for time.Now().Before(deadline) {
		q := url.Values{}
		q.Set("limit", "200")
		q.Set("order", "asc")
		events, err := cli.QuerySessionEvents(ctx, sessionID, q)
		if err != nil {
			t.Fatalf("07c query session events: %v", err)
		}
		observed = events
		for _, ev := range events {
			if pred(ev) {
				return ev
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	var summaries []string
	for _, ev := range observed {
		summaries = append(summaries, fmt.Sprintf("%s:%v", ev.Type, ev.Fields))
	}
	t.Fatalf("07c did not emit %s; observed %s", label, strings.Join(summaries, "\n"))
	return types.Event{}
}
```

- [ ] **Step 2: Run the core 07c tests and confirm the red state**

Run:

```bash
go test -v -tags=integration ./internal/integration/... -run 'TestDB07CRealPostgresProxySQLAndUnavoidability|TestDB07CRejectsListenerAccessOutsideOwningSession' -count=1
```

Expected before the previous tasks are present: compile failure for `DBProxySocketDir` or missing `db07cclient`. Expected after Tasks 1-3 are present: Docker-backed tests run and any failure identifies startup, SQL behavior, bypass event, or listener auth event.

- [ ] **Step 3: Resolve compile issues without weakening assertions**

Use these rules while making the file compile:

- Keep the build tag `//go:build integration && linux`.
- Keep `db07c-client` execution inside `cli.Exec` for proxy-path SQL; host-process `pgx` connections may only seed and inspect upstream state.
- Keep direct listener auth failure outside the AgentSH session by using `env.server.Exec`.
- Keep direct TCP bypass inside the AgentSH-governed session by using `cli.Exec` with `-dsn postgres://app:secret@pg07c:5432/app?sslmode=disable`.
- Keep event polling through `cli.QuerySessionEvents` so the suite proves API-visible audit data.

- [ ] **Step 4: Run the core tests and commit**

Run:

```bash
go test -v -tags=integration ./internal/integration/... -run 'TestDB07CRealPostgresProxySQLAndUnavoidability|TestDB07CRejectsListenerAccessOutsideOwningSession' -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/integration/db_postgres_07c_test.go
git commit -m "test: add db 07c postgres integration core"
```

## Task 5: Add Cancel And COPY Real-Postgres Assertions

**Files:**
- Modify: `internal/integration/db_postgres_07c_test.go`

- [ ] **Step 1: Add cancel and COPY tests**

Append these tests to `internal/integration/db_postgres_07c_test.go`:

```go
func TestDB07CRealPostgresCancelRequest(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	cancel := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "cancel", "-sql", "select pg_sleep(10)", "-timeout", "5s")
	if cancel.SQLState != "57014" && !strings.Contains(strings.ToLower(cancel.Error), "cancel") {
		t.Fatalf("07c cancel request did not cancel pg_sleep: %+v", cancel)
	}

	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		if ev.Type != "db_statement" {
			return false
		}
		decision, _ := ev.Fields["decision"].(map[string]any)
		return ev.Fields["operation_subtype"] == "cancel_request" || decision["rule_kind"] == "cancel"
	}, "db_statement cancel_request")
}

func TestDB07CRealPostgresCopyEvents(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	copyTo := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "copy-to", "-sql", "COPY (SELECT note FROM db07c_copy ORDER BY id) TO STDOUT WITH CSV")
	if copyTo.BytesOut == 0 {
		t.Fatalf("07c COPY TO returned no bytes: %+v", copyTo)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		if ev.Type != "db_statement" || ev.Operation != "bulk_export" {
			return false
		}
		result, _ := ev.Fields["result"].(map[string]any)
		bytesOut, _ := result["bytes_out"].(float64)
		return bytesOut > 0
	}, "db_statement bulk_export")

	copyFrom := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "copy-from", "-sql", "COPY db07c_copy(note) FROM STDIN WITH CSV", "-data", "from-copy\n")
	if copyFrom.BytesIn == 0 {
		t.Fatalf("07c COPY FROM sent no bytes: %+v", copyFrom)
	}
	assertCopyRow07C(t, ctx, env.hostDSN, "from-copy")
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		if ev.Type != "db_statement" || ev.Operation != "bulk_load" {
			return false
		}
		result, _ := ev.Fields["result"].(map[string]any)
		bytesIn, _ := result["bytes_in"].(float64)
		return bytesIn > 0
	}, "db_statement bulk_load")
}

func assertCopyRow07C(t *testing.T, ctx context.Context, dsn, note string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("07c connect host Postgres: %v", err)
	}
	defer conn.Close(ctx)
	var count int
	if err := conn.QueryRow(ctx, "select count(*) from db07c_copy where note = $1", note).Scan(&count); err != nil {
		t.Fatalf("07c query copy row: %v", err)
	}
	if count != 1 {
		t.Fatalf("07c COPY FROM row count for %q = %d, want 1", note, count)
	}
}
```

- [ ] **Step 2: Run the cancel/COPY tests**

Run:

```bash
go test -v -tags=integration ./internal/integration/... -run 'TestDB07CRealPostgresCancelRequest|TestDB07CRealPostgresCopyEvents' -count=1
```

Expected: PASS. If this fails because `db_statement` events are absent, return to Task 2 and verify `EmitStatement` appends and publishes events. If this fails because COPY or cancel protocol behavior differs against real Postgres, fix the production proxy behavior under `internal/db/proxy/postgres` with a focused unit test in that package before relaxing the integration assertion.

- [ ] **Step 3: Run all 07c tests and commit**

Run:

```bash
go test -v -tags=integration ./internal/integration/... -run TestDB07C -count=1
```

Expected: PASS.

Commit:

```bash
git add internal/integration/db_postgres_07c_test.go internal/db/proxy/postgres
git commit -m "test: cover db 07c postgres protocol features"
```

If `internal/db/proxy/postgres` was not changed, use:

```bash
git add internal/integration/db_postgres_07c_test.go
git commit -m "test: cover db 07c postgres protocol features"
```

## Task 6: Update Plan 07 And DB Access Documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-05-13-db-plan-07-split-unavoidability-design.md`
- Modify: `docs/agentsh-db-access-spec.md`
- Modify: `docs/superpowers/specs/2026-05-13-db-plan-07c-integration-suite-design.md`

- [ ] **Step 1: Update Plan 07 split document**

In `docs/superpowers/specs/2026-05-13-db-plan-07-split-unavoidability-design.md`, update the closeout language so it says:

```markdown
Plan 07c is the CI closeout gate: it runs `go test -v -tags=integration ./internal/integration/...` against a real `postgres:16-alpine` container, exercises the AgentSH Postgres proxy path through a governed session, and asserts `db_bypass_attempt` plus `db_listener_auth_fail` lifecycle events. Plan 07 is complete only after that suite passes in CI.
```

Also update the final status sentence to:

```markdown
After 07c passes in CI, Plan 07 is complete and DB Access Phase 1 recommends `policies.db.unavoidability: enforce` for declared Postgres services inside the AgentSH-governed process tree.
```

- [ ] **Step 2: Update the DB access spec operator guidance**

In `docs/agentsh-db-access-spec.md`, update the Plan 07/Phase 1 guidance near the unavoidability sections so it contains these points in prose:

```markdown
For declared Phase 1 Postgres services, `policies.db.unavoidability: enforce` is the high-assurance recommendation once the Plan 07c real-Postgres integration suite is passing in CI. The claim is scoped to processes inside the AgentSH-governed process tree, declared DB services, and an uncompromised AgentSH supervisor plus DB proxy. Aurora Postgres, Redshift, CockroachDB, MySQL, and MariaDB remain outside the automated high-assurance CI claim for Phase 1.
```

- [ ] **Step 3: Mark the 07c design as implemented**

In `docs/superpowers/specs/2026-05-13-db-plan-07c-integration-suite-design.md`, change:

```markdown
**Status:** Approved for implementation planning.
```

to:

```markdown
**Status:** Implemented.
```

- [ ] **Step 4: Check docs and commit**

Run:

```bash
git diff --check
```

Expected: no output.

Commit:

```bash
git add docs/superpowers/specs/2026-05-13-db-plan-07-split-unavoidability-design.md docs/agentsh-db-access-spec.md docs/superpowers/specs/2026-05-13-db-plan-07c-integration-suite-design.md
git commit -m "docs: close db plan 07 guidance"
```

## Task 7: Final Verification

**Files:**
- Verify the full branch.

- [ ] **Step 1: Run focused unit verification**

Run:

```bash
go test ./internal/session ./internal/api -run 'TestSessionSnapshotIncludesDBProxySocketDir|TestDBStatementToEvent|TestDBAuditSinkEmitStatement|TestDBLifecycleToEvent' -count=1
```

Expected: PASS.

- [ ] **Step 2: Run the 07c integration gate**

Run:

```bash
go test -v -tags=integration ./internal/integration/... -run TestDB07C -count=1
```

Expected: PASS.

- [ ] **Step 3: Run the complete integration suite**

Run:

```bash
go test -v -tags=integration ./internal/integration/...
```

Expected: PASS.

- [ ] **Step 4: Run DB/API and full unit suites**

Run:

```bash
go test ./internal/db/... ./internal/api/...
go test -p 2 ./...
```

Expected: both commands PASS.

- [ ] **Step 5: Run Windows build and whitespace verification**

Run:

```bash
GOOS=windows go build ./...
git diff --check
```

Expected: both commands PASS with no whitespace errors.

- [ ] **Step 6: Commit any final fixes**

If verification required code or docs fixes, commit them:

```bash
git status --short
git add pkg/types/sessions.go internal/session/manager.go internal/session/manager_test.go internal/api/db_lifecycle_sink.go internal/api/db_lifecycle_sink_test.go internal/integration/db07cclient/main.go internal/integration/db_postgres_07c_test.go docs/superpowers/specs/2026-05-13-db-plan-07-split-unavoidability-design.md docs/agentsh-db-access-spec.md docs/superpowers/specs/2026-05-13-db-plan-07c-integration-suite-design.md internal/db/proxy/postgres
git commit -m "test: finish db plan 07c integration suite"
```

If there are no final fixes, leave the branch at the last task commit.

## Self-Review

- Spec coverage: Task 1 covers API socket discovery. Task 2 covers queryable DB statement, cancel, and COPY events. Task 3 provides the real `pgx` client used inside and outside governed sessions. Task 4 covers real Postgres SQL flows, deny-before-upstream mutation, direct TCP bypass, and listener SessionID authentication. Task 5 covers CancelRequest and COPY behavior against real Postgres. Task 6 covers operator closeout and high-assurance recommendation scope. Task 7 covers local and CI verification commands from the design.
- Placeholder scan: the plan avoids empty implementation markers and includes concrete files, code, commands, and expected outcomes for each task.
- Type consistency: session field name is `DBProxySocketDir` with JSON key `db_proxy_socket_dir`; DB statement event type is `db_statement`; integration helper path is `/usr/local/bin/db07c-client`; DB service name is `appdb`; Postgres network alias is `pg07c`; direct container DSN is `postgres://app:secret@pg07c:5432/app?sslmode=disable`.
