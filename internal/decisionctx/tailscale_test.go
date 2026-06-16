package decisionctx

import (
	"context"
	"errors"
	"testing"
)

func TestTailscaleSource_OverridesOSUser(t *testing.T) {
	fake := func(_ context.Context, _ string) (string, bool, error) {
		return "eran@example.com", true, nil
	}
	dc := DecisionContext{User: User{Value: "alice", Source: SourceOS}}
	src := newTailscaleSource("", fake)
	if err := src.Resolve(context.Background(), &dc); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dc.User.Value != "eran@example.com" || dc.User.Source != SourceTailscale {
		t.Errorf("user = %+v, want {eran@example.com tailscale}", dc.User)
	}
}

func TestTailscaleSource_AbsentLeavesOSUser(t *testing.T) {
	fake := func(_ context.Context, _ string) (string, bool, error) {
		return "", false, errors.New("dial: no such file")
	}
	dc := DecisionContext{User: User{Value: "alice", Source: SourceOS}}
	src := newTailscaleSource("", fake)
	if err := src.Resolve(context.Background(), &dc); err != nil {
		t.Fatalf("Resolve should swallow unavailability: %v", err)
	}
	if dc.User.Value != "alice" || dc.User.Source != SourceOS {
		t.Errorf("user = %+v, want unchanged {alice os}", dc.User)
	}
}

func TestTailscaleSource_AvailableButEmptyLogin(t *testing.T) {
	fake := func(_ context.Context, _ string) (string, bool, error) {
		return "", true, nil
	}
	dc := DecisionContext{User: User{Value: "alice", Source: SourceOS}}
	src := newTailscaleSource("", fake)
	if err := src.Resolve(context.Background(), &dc); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dc.User.Value != "alice" || dc.User.Source != SourceOS {
		t.Errorf("user = %+v, want unchanged {alice os}", dc.User)
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	js := []byte(`{"Self":{"UserID":12345},"User":{"12345":{"LoginName":"eran@example.com"}}}`)
	login, ok := parseTailscaleStatus(js)
	if !ok || login != "eran@example.com" {
		t.Fatalf("parseTailscaleStatus = %q,%v want eran@example.com,true", login, ok)
	}
	if _, ok := parseTailscaleStatus([]byte(`{"Self":null}`)); ok {
		t.Errorf("expected ok=false when Self is null")
	}
	if _, ok := parseTailscaleStatus([]byte("not json")); ok {
		t.Errorf("expected ok=false for malformed JSON")
	}
}
