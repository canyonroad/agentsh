package decisionctx

import (
	"context"
	"errors"
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

func TestResolver_ExtraSource_CopiesAndIsolates(t *testing.T) {
	orig := map[string]string{"key1": "val1", "key2": "val2"}
	r := &Resolver{sources: []Source{
		extraSource{extra: orig},
	}}
	dc, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(dc.Extra) != 2 {
		t.Fatalf("extra len = %d, want 2", len(dc.Extra))
	}
	if dc.Extra["key1"] != "val1" || dc.Extra["key2"] != "val2" {
		t.Errorf("extra = %v, want {key1:val1 key2:val2}", dc.Extra)
	}
	// Mutating the returned map must not affect the source map.
	dc.Extra["key1"] = "mutated"
	if orig["key1"] != "val1" {
		t.Errorf("source map was mutated via returned dc.Extra")
	}
}

func TestResolver_SwallowsSourceError_OtherFieldsPopulated(t *testing.T) {
	r := &Resolver{sources: []Source{
		staticHostname("host-2"),
		errorSource{},
		staticOSUser("bob"),
	}}
	dc, err := r.Resolve(context.Background())
	// Resolver.Resolve must never return a non-nil error.
	if err != nil {
		t.Fatalf("Resolve returned error %v, want nil", err)
	}
	// Fields set by non-failing sources must still be populated.
	if dc.Hostname != "host-2" {
		t.Errorf("hostname = %q, want host-2", dc.Hostname)
	}
	if dc.User.Value != "bob" {
		t.Errorf("user = %+v, want {bob os}", dc.User)
	}
}

// errorSource is a stub whose Resolve always returns an error.
type errorSource struct{}

func (errorSource) Name() string { return "error-stub" }
func (errorSource) Resolve(_ context.Context, _ *DecisionContext) error {
	return errors.New("stub error")
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

func TestNewResolver_IncludesTailscaleWhenEnabled(t *testing.T) {
	r := NewResolver(Config{Tags: []string{"x"}, TailscaleEnabled: true})
	if !hasSource(r, "tailscale") {
		t.Errorf("tailscale source missing when enabled")
	}
	r2 := NewResolver(Config{TailscaleEnabled: false})
	if hasSource(r2, "tailscale") {
		t.Errorf("tailscale source present when disabled")
	}
}

func hasSource(r *Resolver, name string) bool {
	for _, s := range r.sources {
		if s.Name() == name {
			return true
		}
	}
	return false
}
