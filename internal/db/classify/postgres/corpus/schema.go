// Package corpus declares the on-disk shape of classifier golden fixtures.
// The harness in corpus_test.go loads every *.yaml in this directory and
// asserts (Classify, Evaluate) against each row.
package corpus

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Row is one corpus fixture. Each .yaml file contains exactly one Row.
type Row struct {
	Name        string `yaml:"name"`
	SpecRef     string `yaml:"spec_ref"`
	Description string `yaml:"description"`

	SQL     string `yaml:"sql"`
	Dialect string `yaml:"dialect"` // postgres | aurora_postgres | cockroachdb | redshift; default postgres
	Session struct {
		SearchPath        []string `yaml:"search_path,omitempty"`
		DefaultSearchPath []string `yaml:"default_search_path,omitempty"`
		TempTables        []string `yaml:"temp_tables,omitempty"`
		Role              string   `yaml:"role,omitempty"`
		InTransaction     bool     `yaml:"in_transaction,omitempty"`
	} `yaml:"session,omitempty"`
	Options struct {
		EscalateUnknownFunctions bool     `yaml:"escalate_unknown_functions,omitempty"`
		SafeFunctionAllowlist    []string `yaml:"safe_function_allowlist,omitempty"`
	} `yaml:"options,omitempty"`

	ExpectedClassification []ExpectedStatement `yaml:"expected_classification"`
	ExpectedDecision       *ExpectedDecision   `yaml:"expected_decision_under_sample_policy,omitempty"`
}

type ExpectedStatement struct {
	RawVerb        string           `yaml:"raw_verb,omitempty"`
	PrimaryGroup   string           `yaml:"primary_group"`
	PrimarySubtype string           `yaml:"primary_subtype,omitempty"`
	Effects        []ExpectedEffect `yaml:"effects"`
	ErrorPrefix    string           `yaml:"error_prefix,omitempty"`
	TopResolution  string           `yaml:"top_resolution,omitempty"`
}

type ExpectedEffect struct {
	Group      string           `yaml:"group"`
	Subtype    string           `yaml:"subtype,omitempty"`
	Objects    []ExpectedObject `yaml:"objects,omitempty"`
	Resolution string           `yaml:"resolution,omitempty"`
}

type ExpectedObject struct {
	Kind   string `yaml:"kind"`
	Schema string `yaml:"schema,omitempty"`
	Name   string `yaml:"name,omitempty"`
	Host   string `yaml:"host,omitempty"`
	Port   int    `yaml:"port,omitempty"`
	Path   string `yaml:"path,omitempty"`
	Argv0  string `yaml:"argv0,omitempty"`
}

type ExpectedDecision struct {
	Verb     string `yaml:"verb"`
	RuleName string `yaml:"rule_name,omitempty"`
	Reason   string `yaml:"reason_contains,omitempty"`
}

// LoadAll reads every *.yaml under dir and returns the rows in filename order.
func LoadAll(dir string) ([]Row, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	out := make([]Row, 0, len(matches))
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		var r Row
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if r.Name == "" {
			r.Name = filepath.Base(p)
		}
		out = append(out, r)
	}
	return out, nil
}
