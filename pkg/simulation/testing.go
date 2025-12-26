package simulation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyTestCase represents a single policy test case.
type PolicyTestCase struct {
	Name        string         `yaml:"name" json:"name"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
	Operation   TestOperation  `yaml:"operation" json:"operation"`
	Expected    ExpectedResult `yaml:"expected" json:"expected"`
}

// TestOperation defines the operation to test.
type TestOperation struct {
	Type        string            `yaml:"type" json:"type"`
	Path        string            `yaml:"path,omitempty" json:"path,omitempty"`
	Domain      string            `yaml:"domain,omitempty" json:"domain,omitempty"`
	Port        int               `yaml:"port,omitempty" json:"port,omitempty"`
	Variable    string            `yaml:"variable,omitempty" json:"variable,omitempty"`
	Command     string            `yaml:"command,omitempty" json:"command,omitempty"`
	ProcessName string            `yaml:"process_name,omitempty" json:"process_name,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// ToOperation converts TestOperation to Operation.
func (t *TestOperation) ToOperation() *Operation {
	return &Operation{
		Type:        t.Type,
		Path:        t.Path,
		Domain:      t.Domain,
		Variable:    t.Variable,
		ProcessName: t.ProcessName,
		Metadata:    t.Metadata,
	}
}

// ExpectedResult defines the expected outcome of a test.
type ExpectedResult struct {
	Decision   string `yaml:"decision" json:"decision"`
	PolicyRule string `yaml:"policy_rule,omitempty" json:"policy_rule,omitempty"`
	RedirectTo string `yaml:"redirect_to,omitempty" json:"redirect_to,omitempty"`
	Message    string `yaml:"message,omitempty" json:"message,omitempty"`
}

// PolicyTestFile represents a file containing test cases.
type PolicyTestFile struct {
	Tests []PolicyTestCase `yaml:"tests" json:"tests"`
}

// TestResults contains the results of running policy tests.
type TestResults struct {
	Passed  int            `json:"passed"`
	Failed  int            `json:"failed"`
	Skipped int            `json:"skipped"`
	Total   int            `json:"total"`
	Errors  []TestFailure  `json:"errors,omitempty"`
}

// TestFailure describes a failed test.
type TestFailure struct {
	TestName    string         `json:"test_name"`
	Description string         `json:"description,omitempty"`
	Operation   TestOperation  `json:"operation"`
	Expected    ExpectedResult `json:"expected"`
	Got         TestResult     `json:"got"`
	Error       string         `json:"error,omitempty"`
}

// TestResult is the actual result from evaluation.
type TestResult struct {
	Decision   string `json:"decision"`
	PolicyRule string `json:"policy_rule,omitempty"`
	RedirectTo string `json:"redirect_to,omitempty"`
	Message    string `json:"message,omitempty"`
}

// PolicyEvaluator evaluates operations against policies.
type PolicyEvaluator interface {
	Evaluate(op *Operation) TestResult
}

// PolicyTester runs policy tests.
type PolicyTester struct {
	evaluator PolicyEvaluator
}

// NewPolicyTester creates a new policy tester.
func NewPolicyTester(evaluator PolicyEvaluator) *PolicyTester {
	return &PolicyTester{
		evaluator: evaluator,
	}
}

// RunTests runs a set of test cases.
func (p *PolicyTester) RunTests(tests []PolicyTestCase) *TestResults {
	results := &TestResults{
		Total: len(tests),
	}

	for _, test := range tests {
		result := p.evaluator.Evaluate(test.Operation.ToOperation())

		if p.compareResults(test.Expected, result) {
			results.Passed++
		} else {
			results.Failed++
			results.Errors = append(results.Errors, TestFailure{
				TestName:    test.Name,
				Description: test.Description,
				Operation:   test.Operation,
				Expected:    test.Expected,
				Got:         result,
			})
		}
	}

	return results
}

// RunTestFile runs tests from a file.
func (p *PolicyTester) RunTestFile(path string) (*TestResults, error) {
	tests, err := LoadTestFile(path)
	if err != nil {
		return nil, err
	}
	return p.RunTests(tests), nil
}

// RunTestDir runs all test files in a directory.
func (p *PolicyTester) RunTestDir(dir string) (*TestResults, error) {
	combined := &TestResults{}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !isTestFile(path) {
			return nil
		}

		results, err := p.RunTestFile(path)
		if err != nil {
			combined.Skipped++
			combined.Errors = append(combined.Errors, TestFailure{
				TestName: path,
				Error:    err.Error(),
			})
			return nil
		}

		combined.Passed += results.Passed
		combined.Failed += results.Failed
		combined.Total += results.Total
		combined.Errors = append(combined.Errors, results.Errors...)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return combined, nil
}

// compareResults compares expected and actual results.
func (p *PolicyTester) compareResults(expected ExpectedResult, got TestResult) bool {
	if expected.Decision != got.Decision {
		return false
	}
	if expected.PolicyRule != "" && expected.PolicyRule != got.PolicyRule {
		return false
	}
	if expected.RedirectTo != "" && expected.RedirectTo != got.RedirectTo {
		return false
	}
	return true
}

// isTestFile checks if a file is a test file.
func isTestFile(path string) bool {
	ext := filepath.Ext(path)
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	base := filepath.Base(path)
	return strings.HasSuffix(strings.TrimSuffix(base, ext), "_test") ||
		strings.HasSuffix(strings.TrimSuffix(base, ext), "-test")
}

// LoadTestFile loads test cases from a YAML file.
func LoadTestFile(path string) ([]PolicyTestCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading test file: %w", err)
	}

	var file PolicyTestFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing test file: %w", err)
	}

	return file.Tests, nil
}

// SaveTestFile saves test cases to a YAML file.
func SaveTestFile(path string, tests []PolicyTestCase) error {
	file := PolicyTestFile{Tests: tests}

	data, err := yaml.Marshal(file)
	if err != nil {
		return fmt.Errorf("marshaling tests: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Summary returns a human-readable summary of test results.
func (r *TestResults) Summary() string {
	if r.Total == 0 {
		return "No tests run"
	}

	status := "PASS"
	if r.Failed > 0 {
		status = "FAIL"
	}

	return fmt.Sprintf("%s: %d/%d tests passed (%d failed, %d skipped)",
		status, r.Passed, r.Total, r.Failed, r.Skipped)
}

// Success returns true if all tests passed.
func (r *TestResults) Success() bool {
	return r.Failed == 0 && r.Total > 0
}
