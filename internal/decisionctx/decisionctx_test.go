package decisionctx

import (
	"context"
	"testing"
)

func TestResolver_HostnameTagsOSUser(t *testing.T) {
	r := &Resolver{sources: []Source{
		staticHostname("host-1"),
		newTagsSource([]string{"b", "a"}),
		staticOSUser("alice"),
	}}
	dc, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dc.Hostname != "host-1" {
		t.Errorf("hostname = %q, want host-1", dc.Hostname)
	}
	if len(dc.Tags) != 2 || dc.Tags[0] != "a" || dc.Tags[1] != "b" {
		t.Errorf("tags = %v, want sorted [a b]", dc.Tags)
	}
	if dc.User.Value != "alice" || dc.User.Source != SourceOS {
		t.Errorf("user = %+v, want {alice os}", dc.User)
	}
}

type staticHostname string

func (s staticHostname) Name() string { return "hostname" }
func (s staticHostname) Resolve(_ context.Context, into *DecisionContext) error {
	into.Hostname = string(s)
	return nil
}

type staticOSUser string

func (s staticOSUser) Name() string { return "os-user" }
func (s staticOSUser) Resolve(_ context.Context, into *DecisionContext) error {
	into.User = User{Value: string(s), Source: SourceOS}
	return nil
}
