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
	"sync"
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
	client            *client.Client
	server            testcontainers.Container
	hostDSN           string
	containerDSN      string
	postgresContainer testcontainers.Container
	networkName       string
	cleanup           func()
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

	allow := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select '07c-ok' from db07c_guard where id = 1", "-simple")
	if allow.Scalar != "07c-ok" {
		t.Fatalf("07c real Postgres proxy did not return rows through appdb: %+v", allow)
	}

	extended := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from db07c_guard where id = 1")
	if extended.Scalar != "seed" {
		t.Fatalf("07c extended query through appdb returned %+v", extended)
	}

	simpleDeny := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "exec", "-sql", "insert into db07c_guard(id, note) values (2, 'simple-denied')", "-simple")
	if simpleDeny.OK || (simpleDeny.SQLState == "" && simpleDeny.Error == "") {
		t.Fatalf("07c simple query deny did not fail with SQLSTATE or error: %+v", simpleDeny)
	}
	assertGuardCount07C(t, ctx, env.hostDSN, 1)

	extendedDeny := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "exec", "-sql", "insert into db07c_guard(id, note) values (3, 'extended-denied')")
	if extendedDeny.OK || (extendedDeny.SQLState == "" && extendedDeny.Error == "") {
		t.Fatalf("07c extended query deny did not fail with SQLSTATE or error: %+v", extendedDeny)
	}
	assertGuardCount07C(t, ctx, env.hostDSN, 1)

	deny := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "tx-deny", "-sql", "insert into db07c_guard(id, note) values (4, 'tx-denied')")
	if deny.SQLState == "" && deny.Error == "" {
		t.Fatalf("07c in-transaction deny did not report SQLSTATE or error: %+v", deny)
	}
	assertGuardCount07C(t, ctx, env.hostDSN, 1)
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		if ev.Type != "db_statement" || ev.Operation != "write" {
			return false
		}
		decision, _ := ev.Fields["decision"].(map[string]any)
		txContext, _ := ev.Fields["tx_context"].(map[string]any)
		return decision["verb"] == "deny" &&
			txContext["in_transaction"] == true &&
			txContext["deny_action"] == "connection_terminated"
	}, "db_statement in-transaction deny connection_terminated")

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

func TestDB07CRealPostgresCancelRequest(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	warm := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from db07c_guard where id = 1")
	if warm.Scalar != "seed" {
		t.Fatalf("07c warmup query returned %+v", warm)
	}
	cancel := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "cancel", "-sql", "select pg_sleep(10) from db07c_guard where id = 1", "-timeout", "5s")
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

	copyTo := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "copy-to", "-sql", "COPY db07c_copy(note) TO STDOUT WITH CSV")
	if copyTo.BytesOut == 0 {
		t.Fatalf("07c COPY TO returned no bytes: %+v", copyTo)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		if ev.Type != "db_statement" || ev.Operation != "bulk_export" {
			return false
		}
		result, _ := ev.Fields["result"].(map[string]any)
		bytesOut, _ := result["bytes_out"].(float64)
		statementText, _ := ev.Fields["statement_text"].(string)
		return bytesOut > 0 &&
			ev.Fields["statement_redaction"] == "parameters_redacted" &&
			statementText != ""
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
		statementText, _ := ev.Fields["statement_text"].(string)
		return bytesIn > 0 &&
			ev.Fields["statement_redaction"] == "parameters_redacted" &&
			statementText != "" &&
			!strings.Contains(statementText, "from-copy")
	}, "db_statement bulk_load")
}

func startDB07CEnvironment(t *testing.T, ctx context.Context) db07cEnv {
	t.Helper()

	netw, err := tcnetwork.New(ctx, tcnetwork.WithAttachable(), tcnetwork.WithDriver("bridge"))
	if err != nil {
		t.Fatalf("07c create Docker network: %v", err)
	}
	var networkCleanupOnce sync.Once
	cleanupNetwork := func() {
		networkCleanupOnce.Do(func() { _ = netw.Remove(context.Background()) })
	}
	t.Cleanup(cleanupNetwork)

	pgReq := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "app",
			"POSTGRES_PASSWORD": "secret",
			"POSTGRES_DB":       "app",
			// Keep the harness on an auth method the terminate_plaintext_upstream path supports.
			"POSTGRES_INITDB_ARGS": strings.Join([]string{
				"--auth-host=md5",
				"--auth-local=trust",
			}, " "),
		},
		Cmd:            []string{"postgres", "-c", "password_encryption=md5"},
		Networks:       []string{netw.Name},
		NetworkAliases: map[string][]string{netw.Name: {"pg07c"}},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}
	pg, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: pgReq, Started: true})
	if err != nil {
		t.Fatalf("07c start postgres container: %v", err)
	}
	var postgresCleanupOnce sync.Once
	cleanupPostgres := func() {
		postgresCleanupOnce.Do(func() { _ = pg.Terminate(context.Background()) })
	}
	t.Cleanup(cleanupPostgres)

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
	configPath := filepath.Join(temp, "config.yaml")
	writeFile(t, configPath, db07cConfigYAML())
	workspace := filepath.Join(temp, "workspace")
	mustMkdir(t, workspace)

	endpoint, server, serverCleanup := startDB07CServerContainer(t, ctx, netw.Name, agentshBin, clientBin, configPath, policiesDir, workspace)
	var serverCleanupOnce sync.Once
	cleanupServer := func() {
		serverCleanupOnce.Do(serverCleanup)
	}
	t.Cleanup(cleanupServer)
	env := db07cEnv{
		client:            client.New(endpoint, "test-key"),
		server:            server,
		hostDSN:           hostDSN,
		containerDSN:      containerDSN,
		postgresContainer: pg,
		networkName:       netw.Name,
	}
	env.cleanup = func() {
		cleanupServer()
		cleanupPostgres()
		cleanupNetwork()
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
		Privileged:     true,
		CapAdd:         []string{"SYS_ADMIN", "SYS_PTRACE"},
		Networks:       []string{networkName},
		NetworkAliases: map[string][]string{networkName: {"agentsh07c"}},
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
			_ = ctr.Terminate(context.Background())
		}
		t.Fatalf("07c start AgentSH container: %v", err)
	}
	cleanup := func() { _ = ctr.Terminate(context.Background()) }
	returned := false
	defer func() {
		if !returned {
			cleanup()
		}
	}()
	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("07c AgentSH host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "18080/tcp")
	if err != nil {
		t.Fatalf("07c AgentSH mapped port: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())
	returned = true
	return endpoint, ctr, cleanup
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
