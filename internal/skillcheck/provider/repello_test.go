package provider

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRepelloStub(t *testing.T) {
	p := NewRepelloProvider()
	if p.Name() != "repello" {
		t.Errorf("name=%s", p.Name())
	}
	if len(p.Capabilities()) != 0 {
		t.Errorf("v2 stub should have no capabilities; got %+v", p.Capabilities())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := p.Scan(ctx, loadFixture(t, "minimal"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !strings.Contains(resp.Metadata.Error, "not yet implemented") {
		t.Errorf("metadata.error=%q", resp.Metadata.Error)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("stub should produce no findings")
	}
}
