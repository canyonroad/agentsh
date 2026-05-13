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
		cancelResult := make(chan error, 1)
		go func() {
			time.Sleep(250 * time.Millisecond)
			cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			cancelResult <- conn.PgConn().CancelRequest(cancelCtx)
		}()

		_, err := conn.Exec(ctx, sqlText)
		cancelErr := <-cancelResult
		if cancelErr != nil {
			return output{SQLState: sqlState(err), Error: errString(err), ConnectionOpen: ping(context.Background(), conn)}, fmt.Errorf("cancel request delivery failed: %w", cancelErr)
		}
		if err == nil {
			return output{}, errors.New("cancel query unexpectedly completed")
		}
		state := sqlState(err)
		if state != "57014" && !strings.Contains(strings.ToLower(err.Error()), "cancel") {
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

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func write(out output) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}
