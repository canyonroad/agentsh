package ipset

import (
	"net"
	"testing"
)

func TestSet_ContainsIPv4Exact(t *testing.T) {
	s := New()
	if err := s.Add("1.2.3.4"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("expected 1.2.3.4 to be a member")
	}
	if s.Contains(net.ParseIP("1.2.3.5")) {
		t.Fatal("did not expect 1.2.3.5 to be a member")
	}
}

func TestSet_ContainsCIDR(t *testing.T) {
	s := New()
	if err := s.Add("10.0.0.0/8"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("10.255.1.1")) {
		t.Fatal("expected 10.255.1.1 inside 10.0.0.0/8")
	}
	if s.Contains(net.ParseIP("11.0.0.1")) {
		t.Fatal("did not expect 11.0.0.1 inside 10.0.0.0/8")
	}
}

func TestSet_IPv6(t *testing.T) {
	s := New()
	if err := s.Add("2001:db8::/32"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("expected 2001:db8::1 inside 2001:db8::/32")
	}
}

func TestSet_IPv6Exact(t *testing.T) {
	s := New()
	if err := s.Add("2001:db8::1"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !s.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("expected bare IPv6 /128 to be a member")
	}
	if s.Contains(net.ParseIP("2001:db8::2")) {
		t.Fatal("did not expect sibling 2001:db8::2 to be a member")
	}
}

func TestSet_NilAndEmpty(t *testing.T) {
	s := New()
	if s.Contains(nil) {
		t.Fatal("nil IP must never be a member")
	}
	if s.Contains(net.ParseIP("1.2.3.4")) {
		t.Fatal("empty set must contain nothing")
	}
	if s.Len() != 0 {
		t.Fatalf("Len=%d, want 0", s.Len())
	}
}

func TestSet_AddInvalid(t *testing.T) {
	s := New()
	if err := s.Add("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid entry")
	}
}
