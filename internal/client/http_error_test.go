package client

import "testing"

func TestHTTPErrorStringIncludesBodyWhenPresent(t *testing.T) {
	err := &HTTPError{Method: "GET", Path: "/x", Status: "500", StatusCode: 500, Body: "boom"}
	if got := err.Error(); got != "GET /x: 500: boom" {
		t.Fatalf("unexpected error string: %q", got)
	}
}

func TestHTTPErrorStringOmitsBodyWhenEmpty(t *testing.T) {
	err := &HTTPError{Method: "POST", Path: "/y", Status: "400", StatusCode: 400, Body: "   "}
	if got := err.Error(); got != "POST /y: 400" {
		t.Fatalf("unexpected error string: %q", got)
	}
}
