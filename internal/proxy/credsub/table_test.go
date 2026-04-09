package credsub

import (
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
