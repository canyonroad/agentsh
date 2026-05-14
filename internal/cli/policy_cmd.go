package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/policyexplain"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/policy/signing"
	"github.com/agentsh/agentsh/internal/policygen"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	var configPath string
	var dir string

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage policies",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Config file path (defaults to AGENTSH_CONFIG or config.yml)")
	cmd.PersistentFlags().StringVar(&dir, "dir", "", "Policies directory (overrides config policies.dir)")

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List policies in the policies directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			entries, err := os.ReadDir(pdir)
			if err != nil {
				return err
			}
			var names []string
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				n := e.Name()
				if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			return printJSON(cmd, map[string]any{"dir": pdir, "policies": names})
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show NAME_OR_PATH",
		Short: "Show policy as JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			p, err := resolvePolicyPath(pdir, args[0])
			if err != nil {
				return err
			}
			po, err := policy.LoadFromFile(p)
			if err != nil {
				return err
			}
			return printJSON(cmd, po)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "validate NAME_OR_PATH",
		Short: "Validate a policy file (parse + compile)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			p, err := resolvePolicyPath(pdir, args[0])
			if err != nil {
				return err
			}
			po, err := policy.LoadFromFile(p)
			if err != nil {
				return err
			}
			if _, err := policy.NewEngine(po, false, true); err != nil {
				return err
			}
			if _, warns, err := dbpolicy.Decode(po); err != nil {
				return err
			} else {
				printDBPolicyWarnings(cmd, warns)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "ok")
			return nil
		},
	})

	// Generate subcommand
	var (
		genOutput       string
		genName         string
		genThreshold    int
		genIncludeBlock bool
		genArgPatterns  bool
		genDirectDB     bool
		genDBPath       string
	)

	generateCmd := &cobra.Command{
		Use:   "generate <session-id|latest>",
		Short: "Generate a policy from session activity",
		Long: `Generate a restrictive policy based on observed session behavior.

This command analyzes events from a session and creates a policy that
would allow only the operations that were performed during that session.

Examples:
  # Generate policy from latest session
  agentsh policy generate latest --output=ci-policy.yaml

  # Generate with custom name and threshold
  agentsh policy generate abc123 --name=production-build --threshold=10

  # Quick preview to stdout
  agentsh policy generate latest`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionArg := args[0]
			ctx := cmd.Context()

			var sess types.Session
			var events []types.Event
			var err error

			if genDirectDB {
				if genDBPath == "" {
					genDBPath = getenvDefault("AGENTSH_DB_PATH", "./data/events.db")
				}
				sess, events, err = loadReportFromDB(ctx, genDBPath, sessionArg)
			} else {
				cfg := getClientConfig(cmd)
				sess, events, err = loadReportFromAPI(ctx, cfg, sessionArg)
			}

			if err != nil {
				return err
			}

			// Create generator with mock store
			store := &memoryEventStore{events: events}
			gen := policygen.NewGenerator(store)

			opts := policygen.Options{
				Name:           genName,
				Threshold:      genThreshold,
				IncludeBlocked: genIncludeBlock,
				ArgPatterns:    genArgPatterns,
			}

			if opts.Name == "" {
				opts.Name = fmt.Sprintf("generated-%s", truncateSessionID(sess.ID))
			}

			policy, err := gen.Generate(ctx, sess, opts)
			if err != nil {
				return fmt.Errorf("generate policy: %w", err)
			}

			yaml := policygen.FormatYAML(policy, opts.Name)

			if genOutput != "" {
				if err := os.WriteFile(genOutput, []byte(yaml), 0644); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Policy written to %s\n", genOutput)
			} else {
				fmt.Fprint(cmd.OutOrStdout(), yaml)
			}

			return nil
		},
	}

	generateCmd.Flags().StringVar(&genOutput, "output", "", "Output file path (default: stdout)")
	generateCmd.Flags().StringVar(&genName, "name", "", "Policy name (default: generated-<session-id>)")
	generateCmd.Flags().IntVar(&genThreshold, "threshold", 5, "Files in same dir before collapsing to glob")
	generateCmd.Flags().BoolVar(&genIncludeBlock, "include-blocked", true, "Include blocked ops as comments")
	generateCmd.Flags().BoolVar(&genArgPatterns, "arg-patterns", true, "Generate arg patterns for risky commands")
	generateCmd.Flags().BoolVar(&genDirectDB, "direct-db", false, "Query local database directly (offline mode)")
	generateCmd.Flags().StringVar(&genDBPath, "db-path", "", "Path to events database")

	cmd.AddCommand(generateCmd)

	// Keygen subcommand
	var keygenOutput string
	var keygenLabel string
	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 signing keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir := keygenOutput
			if outDir == "" {
				outDir = "."
			}
			kid, err := signing.GenerateKeypair(outDir, keygenLabel)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", kid)
			fmt.Fprintf(cmd.ErrOrStderr(), "Keypair written to %s/\n", outDir)
			return nil
		},
	}
	keygenCmd.Flags().StringVar(&keygenOutput, "output", "", "Output directory (default: current dir)")
	keygenCmd.Flags().StringVar(&keygenLabel, "label", "", "Human-readable label for the key")
	cmd.AddCommand(keygenCmd)

	// Sign subcommand
	var signKey string
	var signOutput string
	var signSigner string
	signCmd := &cobra.Command{
		Use:   "sign POLICY_FILE",
		Short: "Sign a policy file with an Ed25519 private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signKey == "" {
				return fmt.Errorf("--key is required")
			}
			if err := signing.SignFile(args[0], signKey, signOutput, signSigner); err != nil {
				return err
			}
			dest := signOutput
			if dest == "" {
				dest = args[0] + ".sig"
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Signature written to %s\n", dest)
			return nil
		},
	}
	signCmd.Flags().StringVar(&signKey, "key", "", "Path to private key file (required)")
	signCmd.Flags().StringVar(&signOutput, "output", "", "Output path for .sig file (default: <policy>.sig)")
	signCmd.Flags().StringVar(&signSigner, "signer", "", "Human-readable signer label")
	cmd.AddCommand(signCmd)

	// Verify subcommand
	var verifyKeyDir string
	verifyCmd := &cobra.Command{
		Use:   "verify POLICY_FILE",
		Short: "Verify a policy file signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if verifyKeyDir == "" {
				return fmt.Errorf("--key-dir is required")
			}
			ts, err := signing.LoadTrustStore(verifyKeyDir, false)
			if err != nil {
				return fmt.Errorf("load trust store: %w", err)
			}
			result, err := signing.VerifyPolicy(args[0], ts)
			if err != nil {
				return fmt.Errorf("verification failed: %w", err)
			}
			return printJSON(cmd, map[string]any{
				"status":    "valid",
				"key_id":    result.KeyID,
				"signer":    result.Signer,
				"signed_at": result.SignedAt,
			})
		},
	}
	verifyCmd.Flags().StringVar(&verifyKeyDir, "key-dir", "", "Path to trust store directory (required)")
	cmd.AddCommand(verifyCmd)

	cmd.AddCommand(newPolicyDBCmd(configPath, dir))

	return cmd
}

func resolvePolicyDir(configPath, override string) (string, error) {
	if strings.TrimSpace(override) != "" {
		return override, nil
	}
	cfg, _, err := loadLocalConfig(configPath)
	if err == nil && strings.TrimSpace(cfg.Policies.Dir) != "" {
		return cfg.Policies.Dir, nil
	}
	// If no config is available, fall back to local conventions.
	if _, err2 := os.Stat("configs"); err2 == nil {
		return "configs", nil
	}
	return ".", nil
}

func resolvePolicyPath(dir, nameOrPath string) (string, error) {
	if nameOrPath == "" {
		return "", fmt.Errorf("policy name/path is required")
	}
	if strings.ContainsRune(nameOrPath, os.PathSeparator) || strings.HasSuffix(nameOrPath, ".yml") || strings.HasSuffix(nameOrPath, ".yaml") {
		p := nameOrPath
		if !filepath.IsAbs(p) {
			p = filepath.Clean(p)
		}
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		// If it's a relative path inside dir, try that.
		p2 := filepath.Join(dir, nameOrPath)
		if _, err := os.Stat(p2); err == nil {
			return p2, nil
		}
	}
	// CLI resolution remains permissive for direct paths; allowlist enforcement is server-side.
	return policy.ResolvePolicyPath(dir, nameOrPath)
}

func truncateSessionID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func newPolicyDBCmd(configPath, dir string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Inspect database policy behavior",
	}
	cmd.AddCommand(newPolicyDBExplainCmd(configPath, dir))
	return cmd
}

func newPolicyDBExplainCmd(configPath, dir string) *cobra.Command {
	var serviceName string
	var dialect string
	var searchPath string
	var tempTables string
	var catalogFixture string
	var sqlFlag string
	var output string

	cmd := &cobra.Command{
		Use:   "explain POLICY_OR_PATH",
		Short: "Explain DB policy classification, resolution, coverage, and decision",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(serviceName) == "" {
				return fmt.Errorf("--service is required")
			}
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			policyPath, err := resolvePolicyPath(pdir, args[0])
			if err != nil {
				return err
			}
			rootPolicy, err := policy.LoadFromFile(policyPath)
			if err != nil {
				return err
			}
			rs, warns, err := dbpolicy.Decode(rootPolicy)
			if err != nil {
				return err
			}
			sqlText := sqlFlag
			if sqlText == "" {
				raw, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
				sqlText = string(raw)
			}
			if strings.TrimSpace(sqlText) == "" {
				return fmt.Errorf("SQL is required via --sql or stdin")
			}
			if dialect == "" {
				if svc, ok := rs.Service(dbpolicy.ServiceID(serviceName)); ok && svc.Dialect != "" {
					dialect = svc.Dialect
				} else {
					dialect = "postgres"
				}
			}
			report, err := policyexplain.Run(rs, warns, policyexplain.Options{
				SQL:            sqlText,
				Service:        dbpolicy.ServiceID(serviceName),
				Dialect:        dialect,
				SearchPath:     splitCSV(searchPath),
				TempTables:     splitCSV(tempTables),
				CatalogFixture: catalogFixture,
			})
			if err != nil {
				return err
			}
			switch output {
			case "", "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			case "text":
				return printDBExplainText(cmd, report)
			default:
				return fmt.Errorf("--output must be json or text")
			}
		},
	}
	cmd.Flags().StringVar(&serviceName, "service", "", "DB service name (required)")
	cmd.Flags().StringVar(&dialect, "dialect", "", "postgres|aurora_postgres|cockroachdb|redshift")
	cmd.Flags().StringVar(&searchPath, "search-path", "", "comma-separated search path")
	cmd.Flags().StringVar(&tempTables, "temp-tables", "", "comma-separated temp table names")
	cmd.Flags().StringVar(&catalogFixture, "catalog-fixture", "", "YAML catalog fixture path")
	cmd.Flags().StringVar(&sqlFlag, "sql", "", "SQL statement text (default: stdin)")
	cmd.Flags().StringVar(&output, "output", "json", "json|text")
	return cmd
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printDBExplainText(cmd *cobra.Command, report policyexplain.Report) error {
	for _, stmt := range report.Statements {
		fmt.Fprintf(cmd.OutOrStdout(), "statement %d: %s\n", stmt.Index, stmt.RawVerb)
		fmt.Fprintf(cmd.OutOrStdout(), "decision: %s\n", stmt.Decision.Verb)
		if stmt.Decision.RuleName != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "rule: %s\n", stmt.Decision.RuleName)
		}
		for _, eff := range stmt.Effects {
			fmt.Fprintf(cmd.OutOrStdout(), "effect %d: %s resolution=%s\n", eff.Index, eff.Operation, eff.Resolution)
			for _, cov := range eff.Coverage {
				if cov.Covered {
					fmt.Fprintf(cmd.OutOrStdout(), "  covered: %s selector=%s\n", cov.Object, cov.Selector)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "  uncovered: %s reason=%s\n", cov.Object, cov.UncoveredReason)
				}
			}
		}
	}
	if len(report.Warnings) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "warnings:")
		for _, w := range report.Warnings {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", w.Code, w.Message)
		}
	}
	return nil
}

func printDBPolicyWarnings(cmd *cobra.Command, warns []dbpolicy.Warning) {
	for _, w := range warns {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning[%s]", w.Code)
		if w.Rule != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), " rule=%s", w.Rule)
		}
		if w.Field != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), " field=%s", w.Field)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), ": %s\n", w.Message)
	}
}
