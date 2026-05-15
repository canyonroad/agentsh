//go:build integration && linux

package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestDB12RealPostgresDirectProxyPolicyReloadPreservesPreparedRedirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	hostDSN, upstream := startDB12Postgres(t, ctx)
	seedDB12Postgres(t, ctx, hostDSN)

	srv, sock, sink := startDB12DirectProxy(t, upstream, db12RedirectPolicyYAML(upstream, "plan12.users_target_a", "redirect-plan12-a"))
	stop := runServer(t, srv)
	defer stop()

	sockDir := renameSocketForPgx(t, sock, 5452)
	conn, err := pgx.Connect(ctx, db12PGXConnString(sockDir, 5452))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())

	if _, err := conn.Prepare(ctx, "old_redirect", "select note from plan12.users_source where id=$1"); err != nil {
		t.Fatalf("Prepare old_redirect: %v", err)
	}

	var first string
	if err := conn.QueryRow(ctx, "old_redirect", 1).Scan(&first); err != nil {
		t.Fatalf("query old_redirect before reload: %v", err)
	}
	if first != "target-a" {
		t.Fatalf("old_redirect before reload = %q, want target-a", first)
	}

	srv.SetPolicy(loadRuleSet(t, db12RedirectPolicyYAML(upstream, "plan12.users_target_b", "redirect-plan12-b")))

	var second string
	if err := conn.QueryRow(ctx, "old_redirect", 1).Scan(&second); err != nil {
		t.Fatalf("query old_redirect after reload: %v", err)
	}
	if second != "target-a" {
		t.Fatalf("old_redirect after reload = %q, want target-a", second)
	}

	var third string
	if err := conn.QueryRow(ctx, "select note from plan12.users_source where id = $1", 1).Scan(&third); err != nil {
		t.Fatalf("query new statement after reload: %v", err)
	}
	if third != "target-b" {
		t.Fatalf("new statement after reload = %q, want target-b", third)
	}

	evs := collectDB12RedirectEvents(t, sink, 3, 3*time.Second)
	targets := []string{evs[0].RedirectTargetRelation, evs[1].RedirectTargetRelation, evs[2].RedirectTargetRelation}
	if fmt.Sprint(targets) != "[plan12.users_target_a plan12.users_target_a plan12.users_target_b]" {
		t.Fatalf("redirect targets = %v", targets)
	}
}

func startDB12Postgres(t *testing.T, ctx context.Context) (hostDSN string, upstream string) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "app",
			"POSTGRES_PASSWORD": "secret",
			"POSTGRES_DB":       "app",
			"POSTGRES_INITDB_ARGS": strings.Join([]string{
				"--auth-host=md5",
				"--auth-local=trust",
			}, " "),
		},
		Cmd: []string{"postgres", "-c", "password_encryption=md5"},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })

	host, err := pg.Host(ctx)
	if err != nil {
		t.Fatalf("postgres host: %v", err)
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("postgres mapped port: %v", err)
	}
	return fmt.Sprintf("postgres://app:secret@%s:%s/app?sslmode=disable", host, port.Port()), fmt.Sprintf("%s:%s", host, port.Port())
}

func seedDB12Postgres(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect host Postgres: %v", err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `
drop schema if exists plan12 cascade;
create schema plan12;
create table plan12.users_source(id int primary key, note text);
create table plan12.users_target_a(id int primary key, note text);
create table plan12.users_target_b(id int primary key, note text);
insert into plan12.users_source(id, note) values (1, 'source');
insert into plan12.users_target_a(id, note) values (1, 'target-a');
insert into plan12.users_target_b(id, note) values (1, 'target-b');
`)
	if err != nil {
		t.Fatalf("seed Postgres: %v", err)
	}
}

func startDB12DirectProxy(t *testing.T, upstream, policyYAML string) (*Server, string, *events.SyncSink) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "appdb.sock")
	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability:  service.UnavoidabilityObserve,
		StateDir:        t.TempDir(),
		Sink:            sink,
		AgentSessionID:  testAgentSessionID,
		SessionResolver: staticResolver{sessionID: testAgentSessionID, ok: true},
		Policy:          loadRuleSet(t, policyYAML),
		Logger:          slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upstream,
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service: policy.DBService{
				Name:           "appdb",
				Family:         "postgres",
				Dialect:        "postgres",
				Upstream:       upstream,
				TLSMode:        "terminate_plaintext_upstream",
				TrustedNetwork: true,
			},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, sockPath, sink
}

func db12RedirectPolicyYAML(upstream, target, ruleName string) string {
	return `version: 1
name: db12-redirect
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: ` + upstream + `
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-app-connect
    db_service: appdb
    db_user: ["app"]
    database: app
    decision: allow
database_rules:
  - name: ` + ruleName + `
    db_service: appdb
    operations: [read]
    relations: ["plan12.users_source"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: ` + target + `
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
`
}

func db12PGXConnString(sockDir string, port int) string {
	return fmt.Sprintf("host=%s port=%d user=app password=secret dbname=app sslmode=disable", sockDir, port)
}

func collectDB12RedirectEvents(t *testing.T, sink *events.SyncSink, want int, deadline time.Duration) []events.DBEvent {
	t.Helper()
	var out []events.DBEvent
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		for _, ev := range sink.DrainStatements() {
			if ev.Redirected {
				out = append(out, ev)
			}
		}
		if len(out) >= want {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("redirect events = %d, want %d: %+v", len(out), want, out)
	return nil
}
