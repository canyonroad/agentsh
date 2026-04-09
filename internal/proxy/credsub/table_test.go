package credsub

import (
	"errors"
	"testing"
)

func TestNew_ReturnsEmptyTable(t *testing.T) {
	tb := New()
	if tb == nil {
		t.Fatal("New returned nil")
	}
	if got := tb.Len(); got != 0 {
		t.Errorf("new table Len() = %d, want 0", got)
	}
}

func TestAdd_HappyPath(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if got := tb.Len(); got != 1 {
		t.Errorf("Len() after Add = %d, want 1", got)
	}
}

func TestAdd_LengthMismatch(t *testing.T) {
	tb := New()
	err := tb.Add("github", []byte("short"), []byte("longer_real"))
	if !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("Add with length mismatch returned %v, want ErrLengthMismatch", err)
	}
	if got := tb.Len(); got != 0 {
		t.Errorf("Len() after failed Add = %d, want 0", got)
	}
}

func TestAdd_EmptyFake(t *testing.T) {
	tb := New()
	err := tb.Add("github", []byte{}, []byte{})
	if !errors.Is(err, ErrEmptyValue) {
		t.Errorf("Add with empty values returned %v, want ErrEmptyValue", err)
	}
}

func TestAdd_NilFake(t *testing.T) {
	tb := New()
	err := tb.Add("github", nil, nil)
	if !errors.Is(err, ErrEmptyValue) {
		t.Errorf("Add with nil values returned %v, want ErrEmptyValue", err)
	}
}
