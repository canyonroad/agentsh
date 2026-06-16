package decisionctx

import (
	"context"
	"os"
	"os/user"
	"sort"
)

// hostnameSource sets Hostname from os.Hostname().
type hostnameSource struct{}

func (hostnameSource) Name() string { return "hostname" }
func (hostnameSource) Resolve(_ context.Context, into *DecisionContext) error {
	h, err := os.Hostname()
	if err != nil {
		return err // swallowed by Resolver; Hostname stays ""
	}
	into.Hostname = h
	return nil
}

// tagsSource sets a sorted copy of the configured tags.
type tagsSource struct{ tags []string }

func newTagsSource(tags []string) tagsSource {
	cp := append([]string(nil), tags...)
	sort.Strings(cp)
	return tagsSource{tags: cp}
}
func (tagsSource) Name() string { return "config-tags" }
func (s tagsSource) Resolve(_ context.Context, into *DecisionContext) error {
	if len(s.tags) > 0 {
		into.Tags = append([]string(nil), s.tags...)
	}
	return nil
}

// osUserSource fills the User slot from os/user.Current().
type osUserSource struct{}

func (osUserSource) Name() string { return "os-user" }
func (osUserSource) Resolve(_ context.Context, into *DecisionContext) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	into.User = User{Value: u.Username, Source: SourceOS}
	return nil
}

// extraSource copies static config extras.
type extraSource struct{ extra map[string]string }

func (extraSource) Name() string { return "extra" }
func (s extraSource) Resolve(_ context.Context, into *DecisionContext) error {
	if len(s.extra) > 0 {
		into.Extra = map[string]string{}
		for k, v := range s.extra {
			into.Extra[k] = v
		}
	}
	return nil
}
