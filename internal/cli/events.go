package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Watch/query events",
	}

	cmd.AddCommand(newEventsTailCmd())
	cmd.AddCommand(newEventsQueryCmd())
	return cmd
}

func newEventsTailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tail SESSION_ID",
		Short: "Tail live events for a session (SSE)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getClientConfig(cmd)
			c := client.New(cfg.serverAddr, cfg.apiKey)
			body, err := c.StreamSessionEvents(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			defer body.Close()

			sc := bufio.NewScanner(body)
			for sc.Scan() {
				line := sc.Text()
				if strings.HasPrefix(line, "data: ") {
					fmt.Fprintln(cmd.OutOrStdout(), strings.TrimPrefix(line, "data: "))
				}
			}
			return sc.Err()
		},
	}
	return cmd
}

func newEventsQueryCmd() *cobra.Command {
	var (
		sessionID  string
		typesCSV   string
		decision   string
		since      string
		until      string
		pathLike   string
		domainLike string
		textLike   string
		limit      int
		offset     int
		order      string

		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query events (API by default; --direct-db for offline)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if directDB {
				if dbPath == "" {
					dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
				}
				st, err := sqlite.Open(dbPath)
				if err != nil {
					return err
				}
				defer st.Close()

				q, err := buildEventQuery(sessionID, typesCSV, decision, since, until, pathLike, domainLike, textLike, limit, offset, order)
				if err != nil {
					return err
				}
				evs, err := st.QueryEvents(cmd.Context(), q)
				if err != nil {
					return err
				}
				return printJSON(cmd, evs)
			}

			cfg := getClientConfig(cmd)
			c := client.New(cfg.serverAddr, cfg.apiKey)
			params := url.Values{}
			if typesCSV != "" {
				params.Set("type", typesCSV)
			}
			if decision != "" {
				params.Set("decision", decision)
			}
			if since != "" {
				params.Set("since", since)
			}
			if until != "" {
				params.Set("until", until)
			}
			if pathLike != "" {
				params.Set("path_like", pathLike)
			}
			if domainLike != "" {
				params.Set("domain_like", domainLike)
			}
			if textLike != "" {
				params.Set("text_like", textLike)
			}
			if limit != 0 {
				params.Set("limit", fmt.Sprintf("%d", limit))
			}
			if offset != 0 {
				params.Set("offset", fmt.Sprintf("%d", offset))
			}
			if order != "" {
				params.Set("order", order)
			}

			var evs []types.Event
			var err error
			if sessionID != "" {
				evs, err = c.QuerySessionEvents(cmd.Context(), sessionID, params)
			} else {
				evs, err = c.SearchEvents(cmd.Context(), params)
			}
			if err != nil {
				return err
			}
			return printJSON(cmd, evs)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Filter by session ID (or query global events when empty)")
	cmd.Flags().StringVar(&typesCSV, "type", "", "Comma-separated event types")
	cmd.Flags().StringVar(&decision, "decision", "", "Policy decision filter (allow|deny|approve)")
	cmd.Flags().StringVar(&since, "since", "", "Start time (RFC3339) or duration (e.g. 1h)")
	cmd.Flags().StringVar(&until, "until", "", "End time (RFC3339) or duration (e.g. 5m)")
	cmd.Flags().StringVar(&pathLike, "path-like", "", "SQL LIKE pattern for path (e.g. %/secrets/%)")
	cmd.Flags().StringVar(&domainLike, "domain-like", "", "SQL LIKE pattern for domain")
	cmd.Flags().StringVar(&textLike, "text-like", "", "SQL LIKE pattern for raw JSON payload")
	cmd.Flags().IntVar(&limit, "limit", 200, "Result limit")
	cmd.Flags().IntVar(&offset, "offset", 0, "Result offset")
	cmd.Flags().StringVar(&order, "order", "desc", "Sort order: asc|desc")

	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local SQLite directly (offline)")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "SQLite DB path (used with --direct-db)")

	return cmd
}

func buildEventQuery(sessionID, typesCSV, decision, since, until, pathLike, domainLike, textLike string, limit, offset int, order string) (types.EventQuery, error) {
	var q types.EventQuery
	q.SessionID = sessionID
	if typesCSV != "" {
		q.Types = strings.Split(typesCSV, ",")
	}
	if decision != "" {
		d := types.Decision(decision)
		q.Decision = &d
	}
	if since != "" {
		t, err := parseTimeOrAgo(since)
		if err != nil {
			return q, err
		}
		q.Since = &t
	}
	if until != "" {
		t, err := parseTimeOrAgo(until)
		if err != nil {
			return q, err
		}
		q.Until = &t
	}
	q.PathLike = pathLike
	q.DomainLike = domainLike
	q.TextLike = textLike
	q.Limit = limit
	q.Offset = offset
	q.Asc = strings.EqualFold(order, "asc")
	return q, nil
}

func parseTimeOrAgo(s string) (time.Time, error) {
	if strings.ContainsAny(s, "smhdw") && !strings.Contains(s, "T") {
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().UTC().Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func mustLoadEventJSON(path string) ([]types.Event, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var evs []types.Event
	if err := json.Unmarshal(b, &evs); err != nil {
		return nil, err
	}
	return evs, nil
}
