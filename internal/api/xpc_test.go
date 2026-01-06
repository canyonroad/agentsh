//go:build darwin

package api

import (
	"testing"
)

func TestDefaultXPCAllowList_NotEmpty(t *testing.T) {
	if len(DefaultXPCAllowList) == 0 {
		t.Error("DefaultXPCAllowList should not be empty")
	}
	// Check for essential service
	found := false
	for _, svc := range DefaultXPCAllowList {
		if svc == "com.apple.system.logger" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultXPCAllowList should contain com.apple.system.logger")
	}
}

func TestDefaultXPCBlockPrefixes_NotEmpty(t *testing.T) {
	if len(DefaultXPCBlockPrefixes) == 0 {
		t.Error("DefaultXPCBlockPrefixes should not be empty")
	}
	// Check for dangerous prefix
	found := false
	for _, prefix := range DefaultXPCBlockPrefixes {
		if prefix == "com.apple.accessibility." {
			found = true
			break
		}
	}
	if !found {
		t.Error("DefaultXPCBlockPrefixes should contain com.apple.accessibility.")
	}
}
