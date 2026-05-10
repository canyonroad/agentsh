// Command dbclassify-pg is an operator CLI that runs the Plan 03 PostgreSQL
// classifier on stdin and prints a JSON report on stdout. It optionally
// evaluates the resulting ClassifiedStatement against the embedded sample
// policy from internal/db/policy.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("dbclassify-pg", flag.ContinueOnError)
	dialectStr := fs.String("dialect", "postgres", "postgres|aurora_postgres|cockroachdb|redshift")
	searchPath := fs.String("search-path", "", "comma-separated identifiers")
	tempTables := fs.String("temp-tables", "", "comma-separated unqualified names")
	escalate := fs.Bool("escalate-unknown-functions", false, "§7.6 knob")
	noEvaluate := fs.Bool("no-evaluate", false, "skip sample-policy decision")
	if err := fs.Parse(args); err != nil {
		return err
	}

	d, ok := postgres.ParseDialect(*dialectStr)
	if !ok {
		return fmt.Errorf("unknown dialect: %q", *dialectStr)
	}

	sql, err := io.ReadAll(stdin)
	if err != nil {
		return err
	}

	sess := postgres.SessionState{}
	if *searchPath != "" {
		for _, p := range strings.Split(*searchPath, ",") {
			sess.SearchPath = append(sess.SearchPath, strings.ToLower(strings.TrimSpace(p)))
		}
	}
	if *tempTables != "" {
		sess.TempTables = make(map[string]struct{})
		for _, n := range strings.Split(*tempTables, ",") {
			sess.TempTables[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
		}
	}
	opts := postgres.Options{EscalateUnknownFunctions: *escalate}

	stmts, err := postgres.New(d).Classify(string(sql), sess, opts)
	if err != nil {
		return err
	}

	type decisionOut struct {
		Verb     string `json:"verb"`
		RuleName string `json:"rule_name,omitempty"`
		Reason   string `json:"reason,omitempty"`
	}

	type stmtOut struct {
		RawVerb                   string           `json:"raw_verb,omitempty"`
		ParserBackend             string           `json:"parser_backend,omitempty"`
		PrimaryGroup              string           `json:"primary_group,omitempty"`
		Effects                   []effects.Effect `json:"effects"`
		Error                     string           `json:"error,omitempty"`
		DecisionUnderSamplePolicy *decisionOut     `json:"decision_under_sample_policy,omitempty"`
	}

	out := struct {
		Dialect    string    `json:"dialect"`
		Statements []stmtOut `json:"statements"`
	}{Dialect: d.String()}

	var rs *policy.RuleSet
	if !*noEvaluate {
		rs = policy.MustLoadSample()
	}

	for _, s := range stmts {
		row := stmtOut{
			RawVerb:       s.RawVerb,
			ParserBackend: s.ParserBackend.String(),
			Effects:       s.Effects,
			Error:         s.Error,
		}
		if prim, ok := s.Primary(); ok {
			row.PrimaryGroup = prim.Group.String()
		}
		if rs != nil {
			dec := policy.Evaluate(s, rs, "appdb")
			row.DecisionUnderSamplePolicy = &decisionOut{
				Verb:     dec.Verb.String(),
				RuleName: dec.RuleName,
				Reason:   dec.Reason,
			}
		}
		out.Statements = append(out.Statements, row)
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
