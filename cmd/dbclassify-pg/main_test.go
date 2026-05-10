package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_SelectClassification(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-dialect=postgres"}, strings.NewReader("SELECT * FROM customers"), &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	body := out.String()
	if !strings.Contains(body, `"primary_group": "read"`) {
		t.Fatalf("output missing read primary_group:\n%s", body)
	}
	if !strings.Contains(body, `"decision_under_sample_policy"`) {
		t.Fatalf("output missing sample-policy decision:\n%s", body)
	}
}

func TestRun_NoEvaluateSuppressesDecision(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-no-evaluate"}, strings.NewReader("SELECT 1"), &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out.String(), `"decision_under_sample_policy"`) {
		t.Fatalf("decision should be omitted when -no-evaluate is set:\n%s", out.String())
	}
}

func TestRun_UnknownDialect(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"-dialect=foobar"}, strings.NewReader("SELECT 1"), &out)
	if err == nil {
		t.Fatal("expected error on unknown dialect")
	}
}
