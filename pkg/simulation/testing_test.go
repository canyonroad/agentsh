package simulation

import (
	"os"
	"path/filepath"
	"testing"
)

type mockEvaluator struct {
	results map[string]TestResult
}

func (m *mockEvaluator) Evaluate(op *Operation) TestResult {
	key := op.Type + ":" + op.Path
	if result, ok := m.results[key]; ok {
		return result
	}
	return TestResult{Decision: "deny"}
}

func TestPolicyTestCase(t *testing.T) {
	tc := PolicyTestCase{
		Name:        "test_read",
		Description: "Test file read",
		Operation: TestOperation{
			Type: "file_read",
			Path: "/workspace/file.txt",
		},
		Expected: ExpectedResult{
			Decision:   "allow",
			PolicyRule: "workspace",
		},
	}

	op := tc.Operation.ToOperation()
	if op.Type != "file_read" {
		t.Errorf("Type = %v, want file_read", op.Type)
	}
	if op.Path != "/workspace/file.txt" {
		t.Errorf("Path = %v, want /workspace/file.txt", op.Path)
	}
}

func TestNewPolicyTester(t *testing.T) {
	eval := &mockEvaluator{}
	pt := NewPolicyTester(eval)

	if pt == nil {
		t.Fatal("NewPolicyTester returned nil")
	}
}

func TestPolicyTester_RunTests_Pass(t *testing.T) {
	eval := &mockEvaluator{
		results: map[string]TestResult{
			"file_read:/workspace/file.txt": {Decision: "allow", PolicyRule: "workspace"},
		},
	}
	pt := NewPolicyTester(eval)

	tests := []PolicyTestCase{
		{
			Name: "test_workspace_read",
			Operation: TestOperation{
				Type: "file_read",
				Path: "/workspace/file.txt",
			},
			Expected: ExpectedResult{
				Decision:   "allow",
				PolicyRule: "workspace",
			},
		},
	}

	results := pt.RunTests(tests)

	if results.Passed != 1 {
		t.Errorf("Passed = %d, want 1", results.Passed)
	}
	if results.Failed != 0 {
		t.Errorf("Failed = %d, want 0", results.Failed)
	}
	if !results.Success() {
		t.Error("Success() should return true")
	}
}

func TestPolicyTester_RunTests_Fail(t *testing.T) {
	eval := &mockEvaluator{
		results: map[string]TestResult{
			"file_read:/etc/passwd": {Decision: "deny", PolicyRule: "sensitive"},
		},
	}
	pt := NewPolicyTester(eval)

	tests := []PolicyTestCase{
		{
			Name: "test_passwd_read",
			Operation: TestOperation{
				Type: "file_read",
				Path: "/etc/passwd",
			},
			Expected: ExpectedResult{
				Decision: "allow", // Expected allow but will get deny
			},
		},
	}

	results := pt.RunTests(tests)

	if results.Passed != 0 {
		t.Errorf("Passed = %d, want 0", results.Passed)
	}
	if results.Failed != 1 {
		t.Errorf("Failed = %d, want 1", results.Failed)
	}
	if len(results.Errors) != 1 {
		t.Errorf("Errors = %d, want 1", len(results.Errors))
	}
	if results.Success() {
		t.Error("Success() should return false")
	}
}

func TestPolicyTester_RunTests_RedirectMatch(t *testing.T) {
	eval := &mockEvaluator{
		results: map[string]TestResult{
			"file_read:/etc/passwd": {
				Decision:   "redirect",
				RedirectTo: "/honeypot/passwd",
			},
		},
	}
	pt := NewPolicyTester(eval)

	tests := []PolicyTestCase{
		{
			Name: "test_redirect",
			Operation: TestOperation{
				Type: "file_read",
				Path: "/etc/passwd",
			},
			Expected: ExpectedResult{
				Decision:   "redirect",
				RedirectTo: "/honeypot/passwd",
			},
		},
	}

	results := pt.RunTests(tests)
	if results.Failed != 0 {
		t.Errorf("Failed = %d, want 0", results.Failed)
	}
}

func TestTestResults_Summary(t *testing.T) {
	tests := []struct {
		results *TestResults
		want    string
	}{
		{
			results: &TestResults{Total: 0},
			want:    "No tests run",
		},
		{
			results: &TestResults{Passed: 5, Total: 5},
			want:    "PASS: 5/5 tests passed (0 failed, 0 skipped)",
		},
		{
			results: &TestResults{Passed: 3, Failed: 2, Total: 5},
			want:    "FAIL: 3/5 tests passed (2 failed, 0 skipped)",
		},
	}

	for _, tt := range tests {
		got := tt.results.Summary()
		if got != tt.want {
			t.Errorf("Summary() = %q, want %q", got, tt.want)
		}
	}
}

func TestLoadTestFile(t *testing.T) {
	// Create temp test file
	dir := t.TempDir()
	path := filepath.Join(dir, "test_policy_test.yaml")

	content := `tests:
  - name: test_read
    operation:
      type: file_read
      path: /workspace/file.txt
    expected:
      decision: allow
  - name: test_deny
    operation:
      type: file_read
      path: /etc/shadow
    expected:
      decision: deny
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	tests, err := LoadTestFile(path)
	if err != nil {
		t.Fatalf("LoadTestFile error: %v", err)
	}

	if len(tests) != 2 {
		t.Errorf("loaded %d tests, want 2", len(tests))
	}

	if tests[0].Name != "test_read" {
		t.Errorf("tests[0].Name = %q, want test_read", tests[0].Name)
	}
}

func TestSaveTestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output_test.yaml")

	tests := []PolicyTestCase{
		{
			Name: "test_1",
			Operation: TestOperation{
				Type: "file_read",
				Path: "/test",
			},
			Expected: ExpectedResult{
				Decision: "allow",
			},
		},
	}

	if err := SaveTestFile(path, tests); err != nil {
		t.Fatalf("SaveTestFile error: %v", err)
	}

	// Verify file exists and can be loaded
	loaded, err := LoadTestFile(path)
	if err != nil {
		t.Fatalf("LoadTestFile error: %v", err)
	}

	if len(loaded) != 1 {
		t.Errorf("loaded %d tests, want 1", len(loaded))
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"policy_test.yaml", true},
		{"policy-test.yaml", true},
		{"policy_test.yml", true},
		{"policy.yaml", false},
		{"test.txt", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isTestFile(tt.path)
		if got != tt.want {
			t.Errorf("isTestFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPolicyTester_RunTestDir(t *testing.T) {
	eval := &mockEvaluator{
		results: map[string]TestResult{
			"file_read:/workspace/a.txt": {Decision: "allow"},
			"file_read:/workspace/b.txt": {Decision: "allow"},
		},
	}
	pt := NewPolicyTester(eval)

	// Create temp directory with test files
	dir := t.TempDir()

	test1 := `tests:
  - name: test_a
    operation:
      type: file_read
      path: /workspace/a.txt
    expected:
      decision: allow
`
	test2 := `tests:
  - name: test_b
    operation:
      type: file_read
      path: /workspace/b.txt
    expected:
      decision: allow
`
	os.WriteFile(filepath.Join(dir, "a_test.yaml"), []byte(test1), 0644)
	os.WriteFile(filepath.Join(dir, "b_test.yaml"), []byte(test2), 0644)
	os.WriteFile(filepath.Join(dir, "not_a_test.yaml"), []byte("not a test"), 0644)

	results, err := pt.RunTestDir(dir)
	if err != nil {
		t.Fatalf("RunTestDir error: %v", err)
	}

	if results.Passed != 2 {
		t.Errorf("Passed = %d, want 2", results.Passed)
	}
	if results.Total != 2 {
		t.Errorf("Total = %d, want 2", results.Total)
	}
}
