package cli

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/agentsh/agentsh/internal/client"
	"github.com/agentsh/agentsh/internal/report"
	"github.com/agentsh/agentsh/internal/store/sqlite"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var (
		level    string
		output   string
		directDB bool
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "report <session-id|latest>",
		Short: "Generate a session report",
		Long: `Generate a markdown report summarizing session activity.

Examples:
  # Quick summary of latest session
  agentsh report latest --level=summary

  # Detailed report saved to file
  agentsh report abc123 --level=detailed --output=report.md

  # Offline mode using local database
  agentsh report latest --level=summary --direct-db`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate level
			reportLevel := report.Level(level)
			if reportLevel != report.LevelSummary && reportLevel != report.LevelDetailed {
				return fmt.Errorf("invalid level %q: must be 'summary' or 'detailed'", level)
			}

			sessionArg := args[0]
			ctx := cmd.Context()

			var sess types.Session
			var events []types.Event
			var err error

			if directDB {
				// Direct database access (offline mode)
				if dbPath == "" {
					dbPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
				}
				sess, events, err = loadReportFromDB(ctx, dbPath, sessionArg)
			} else {
				// Use API client
				cfg := getClientConfig(cmd)
				sess, events, err = loadReportFromAPI(ctx, cfg, sessionArg)
			}

			if err != nil {
				return err
			}

			// Create mock store for generator
			store := &memoryEventStore{events: events}
			gen := report.NewGenerator(store)

			rpt, err := gen.Generate(ctx, sess, reportLevel)
			if err != nil {
				return fmt.Errorf("generate report: %w", err)
			}

			md := report.FormatMarkdown(rpt)

			// Output to file or stdout
			if output != "" {
				if err := os.WriteFile(output, []byte(md), 0644); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Report written to %s\n", output)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), md)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&level, "level", "", "Report level: summary or detailed (required)")
	cmd.Flags().StringVar(&output, "output", "", "Output file path (default: stdout)")
	cmd.Flags().BoolVar(&directDB, "direct-db", false, "Query local database directly (offline mode)")
	cmd.Flags().StringVar(&dbPath, "db-path", "", "Path to events database (default: ./data/events.db)")
	_ = cmd.MarkFlagRequired("level")

	return cmd
}

// memoryEventStore wraps pre-loaded events for the generator.
type memoryEventStore struct {
	events []types.Event
}

func (m *memoryEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return m.events, nil
}
func (m *memoryEventStore) AppendEvent(ctx context.Context, ev types.Event) error { return nil }
func (m *memoryEventStore) Close() error                                          { return nil }

func loadReportFromAPI(ctx context.Context, cfg *clientConfig, sessionArg string) (types.Session, []types.Event, error) {
	c, err := client.NewForCLI(client.CLIOptions{
		HTTPBaseURL: cfg.serverAddr,
		GRPCAddr:    cfg.grpcAddr,
		APIKey:      cfg.apiKey,
		Transport:   cfg.transport,
	})
	if err != nil {
		return types.Session{}, nil, err
	}

	// Resolve "latest" to actual session ID
	sessionID := sessionArg
	if sessionArg == "latest" {
		sessions, err := c.ListSessions(ctx)
		if err != nil {
			return types.Session{}, nil, fmt.Errorf("list sessions: %w", err)
		}
		if len(sessions) == 0 {
			return types.Session{}, nil, fmt.Errorf("no sessions found")
		}
		// Find most recent by CreatedAt
		latest := sessions[0]
		for _, s := range sessions[1:] {
			if s.CreatedAt.After(latest.CreatedAt) {
				latest = s
			}
		}
		sessionID = latest.ID
	}

	sess, err := c.GetSession(ctx, sessionID)
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("get session: %w (hint: run 'agentsh session list')", err)
	}

	// Query events with ascending order
	q := url.Values{}
	q.Set("order", "asc")
	events, err := c.QuerySessionEvents(ctx, sessionID, q)
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("query events: %w", err)
	}

	return sess, events, nil
}

func loadReportFromDB(ctx context.Context, dbPath, sessionArg string) (types.Session, []types.Event, error) {
	store, err := sqlite.Open(dbPath)
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	// For direct DB mode, we need to get session info from events
	// Query events to find sessions
	sessionID := sessionArg
	if sessionArg == "latest" {
		// Query recent events to find latest session
		events, err := store.QueryEvents(ctx, types.EventQuery{Limit: 1000})
		if err != nil {
			return types.Session{}, nil, fmt.Errorf("query events: %w", err)
		}
		if len(events) == 0 {
			return types.Session{}, nil, fmt.Errorf("no sessions found in database")
		}
		// Group by session, find most recent
		sessions := make(map[string]types.Event)
		for _, ev := range events {
			if _, ok := sessions[ev.SessionID]; !ok {
				sessions[ev.SessionID] = ev
			}
		}
		var latestID string
		var latestTime = events[0].Timestamp
		for sid, ev := range sessions {
			if ev.Timestamp.After(latestTime) {
				latestTime = ev.Timestamp
				latestID = sid
			}
		}
		sessionID = latestID
	}

	events, err := store.QueryEvents(ctx, types.EventQuery{SessionID: sessionID, Asc: true})
	if err != nil {
		return types.Session{}, nil, fmt.Errorf("query events: %w", err)
	}
	if len(events) == 0 {
		return types.Session{}, nil, fmt.Errorf("session %q not found", sessionID)
	}

	// Build minimal session from events
	sess := types.Session{
		ID:        sessionID,
		State:     types.SessionStateCompleted,
		CreatedAt: events[0].Timestamp,
	}

	return sess, events, nil
}
