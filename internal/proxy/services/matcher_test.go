package services

import "testing"

func TestMatcher_LiteralMatch(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})
	name, ok := m.Match("api.github.com")
	if !ok || name != "github" {
		t.Errorf("Match(api.github.com) = (%q, %v), want (github, true)", name, ok)
	}
}

func TestMatcher_LiteralMatch_CaseInsensitive(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})
	name, ok := m.Match("API.GitHub.COM")
	if !ok || name != "github" {
		t.Errorf("Match(API.GitHub.COM) = (%q, %v), want (github, true)", name, ok)
	}
}

func TestMatcher_WildcardMatch(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"*.github.com"}},
	})

	tests := []struct {
		host string
		want bool
	}{
		{"api.github.com", true},
		{"uploads.github.com", true},
		{"github.com", false},          // bare domain doesn't match wildcard
		{"sub.api.github.com", false},  // multi-level doesn't match
	}

	for _, tt := range tests {
		name, ok := m.Match(tt.host)
		if ok != tt.want {
			t.Errorf("Match(%q) ok=%v, want %v (name=%q)", tt.host, ok, tt.want, name)
		}
		if ok && name != "github" {
			t.Errorf("Match(%q) name=%q, want github", tt.host, name)
		}
	}
}

func TestMatcher_PortStripping(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})
	name, ok := m.Match("api.github.com:443")
	if !ok || name != "github" {
		t.Errorf("Match(api.github.com:443) = (%q, %v), want (github, true)", name, ok)
	}
}

func TestMatcher_FirstMatchWins(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "specific", Hosts: []string{"api.example.com"}},
		{Name: "wildcard", Hosts: []string{"*.example.com"}},
	})
	name, ok := m.Match("api.example.com")
	if !ok || name != "specific" {
		t.Errorf("Match(api.example.com) = (%q, %v), want (specific, true)", name, ok)
	}
}

func TestMatcher_NoMatch(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})
	name, ok := m.Match("evil.com")
	if ok {
		t.Errorf("Match(evil.com) = (%q, true), want (\"\", false)", name)
	}
}

func TestMatcher_Empty(t *testing.T) {
	m := NewMatcher(nil)
	_, ok := m.Match("anything.com")
	if ok {
		t.Error("empty matcher should never match")
	}
}

func TestMatcher_TrailingDot(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"api.github.com"}},
	})
	name, ok := m.Match("api.github.com.")
	if !ok || name != "github" {
		t.Errorf("Match(api.github.com.) = (%q, %v), want (github, true)", name, ok)
	}
}

func TestMatcher_IPv6_NoPort(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "local", Hosts: []string{"[::1]"}},
	})
	name, ok := m.Match("[::1]")
	if !ok || name != "local" {
		t.Errorf("Match([::1]) = (%q, %v), want (local, true)", name, ok)
	}
}

func TestMatcher_IPv6_WithPort(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "local", Hosts: []string{"[::1]"}},
	})
	name, ok := m.Match("[::1]:8080")
	if !ok || name != "local" {
		t.Errorf("Match([::1]:8080) = (%q, %v), want (local, true)", name, ok)
	}
}

func TestMatcher_MultipleHosts(t *testing.T) {
	m := NewMatcher([]ServicePattern{
		{Name: "github", Hosts: []string{"api.github.com", "uploads.github.com"}},
	})
	for _, host := range []string{"api.github.com", "uploads.github.com"} {
		name, ok := m.Match(host)
		if !ok || name != "github" {
			t.Errorf("Match(%q) = (%q, %v), want (github, true)", host, name, ok)
		}
	}
}
