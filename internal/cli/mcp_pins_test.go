package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMCPPinsListCmd(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.db")
	os.Setenv("AGENTSH_PINS_PATH", pinPath)
	defer os.Unsetenv("AGENTSH_PINS_PATH")

	cmd := newMCPPinsCmd()
	cmd.SetArgs([]string{"list"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("No pins found")) {
		t.Errorf("Expected 'No pins found', got: %s", buf.String())
	}
}

func TestMCPPinsTrustCmd(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.db")
	os.Setenv("AGENTSH_PINS_PATH", pinPath)
	defer os.Unsetenv("AGENTSH_PINS_PATH")

	cmd := newMCPPinsCmd()
	cmd.SetArgs([]string{"trust", "--server", "filesystem", "--tool", "read_file", "--hash", "abc123def456"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("Pinned filesystem:read_file")) {
		t.Errorf("Expected pin confirmation, got: %s", buf.String())
	}

	// Verify the pin was actually stored by listing
	cmd2 := newMCPPinsCmd()
	cmd2.SetArgs([]string{"list"})
	var buf2 bytes.Buffer
	cmd2.SetOut(&buf2)

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute list: %v", err)
	}

	if !bytes.Contains(buf2.Bytes(), []byte("filesystem")) {
		t.Errorf("Expected filesystem in list, got: %s", buf2.String())
	}
	if !bytes.Contains(buf2.Bytes(), []byte("read_file")) {
		t.Errorf("Expected read_file in list, got: %s", buf2.String())
	}
}

func TestMCPPinsResetCmd(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.db")
	os.Setenv("AGENTSH_PINS_PATH", pinPath)
	defer os.Unsetenv("AGENTSH_PINS_PATH")

	// First trust a tool
	cmd := newMCPPinsCmd()
	cmd.SetArgs([]string{"trust", "--server", "filesystem", "--tool", "read_file", "--hash", "abc123"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute trust: %v", err)
	}

	// Now reset it
	cmd2 := newMCPPinsCmd()
	cmd2.SetArgs([]string{"reset", "--server", "filesystem", "--tool", "read_file"})
	var buf2 bytes.Buffer
	cmd2.SetOut(&buf2)

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute reset: %v", err)
	}

	if !bytes.Contains(buf2.Bytes(), []byte("Pin for filesystem:read_file removed")) {
		t.Errorf("Expected reset confirmation, got: %s", buf2.String())
	}

	// Verify the pin was removed
	cmd3 := newMCPPinsCmd()
	cmd3.SetArgs([]string{"list"})
	var buf3 bytes.Buffer
	cmd3.SetOut(&buf3)

	if err := cmd3.Execute(); err != nil {
		t.Fatalf("Execute list: %v", err)
	}

	if !bytes.Contains(buf3.Bytes(), []byte("No pins found")) {
		t.Errorf("Expected 'No pins found' after reset, got: %s", buf3.String())
	}
}

func TestMCPPinsDiffCmd(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.db")
	os.Setenv("AGENTSH_PINS_PATH", pinPath)
	defer os.Unsetenv("AGENTSH_PINS_PATH")

	// First trust a tool
	cmd := newMCPPinsCmd()
	cmd.SetArgs([]string{"trust", "--server", "filesystem", "--tool", "read_file", "--hash", "abc123def456"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute trust: %v", err)
	}

	// Now diff it
	cmd2 := newMCPPinsCmd()
	cmd2.SetArgs([]string{"diff", "--server", "filesystem", "--tool", "read_file"})
	var buf2 bytes.Buffer
	cmd2.SetOut(&buf2)

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute diff: %v", err)
	}

	if !bytes.Contains(buf2.Bytes(), []byte("Pinned hash: abc123def456")) {
		t.Errorf("Expected pinned hash in diff, got: %s", buf2.String())
	}
}

func TestMCPPinsListCmd_WithServerFilter(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.db")
	os.Setenv("AGENTSH_PINS_PATH", pinPath)
	defer os.Unsetenv("AGENTSH_PINS_PATH")

	// Trust tools on different servers
	cmd := newMCPPinsCmd()
	cmd.SetArgs([]string{"trust", "--server", "server1", "--tool", "tool1", "--hash", "hash1"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute trust 1: %v", err)
	}

	cmd2 := newMCPPinsCmd()
	cmd2.SetArgs([]string{"trust", "--server", "server2", "--tool", "tool2", "--hash", "hash2"})
	var buf2 bytes.Buffer
	cmd2.SetOut(&buf2)
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute trust 2: %v", err)
	}

	// List with filter
	cmd3 := newMCPPinsCmd()
	cmd3.SetArgs([]string{"list", "--server", "server1"})
	var buf3 bytes.Buffer
	cmd3.SetOut(&buf3)

	if err := cmd3.Execute(); err != nil {
		t.Fatalf("Execute list: %v", err)
	}

	output := buf3.String()
	if !bytes.Contains([]byte(output), []byte("server1")) {
		t.Errorf("Expected server1 in filtered list, got: %s", output)
	}
	if bytes.Contains([]byte(output), []byte("server2")) {
		t.Errorf("Expected server2 to be filtered out, got: %s", output)
	}
}

func TestMCPPinsResetCmd_All(t *testing.T) {
	tmpDir := t.TempDir()
	pinPath := filepath.Join(tmpDir, "pins.db")
	os.Setenv("AGENTSH_PINS_PATH", pinPath)
	defer os.Unsetenv("AGENTSH_PINS_PATH")

	// Trust multiple tools
	for _, args := range [][]string{
		{"trust", "--server", "server1", "--tool", "tool1", "--hash", "hash1"},
		{"trust", "--server", "server1", "--tool", "tool2", "--hash", "hash2"},
		{"trust", "--server", "server2", "--tool", "tool3", "--hash", "hash3"},
	} {
		cmd := newMCPPinsCmd()
		cmd.SetArgs(args)
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute trust: %v", err)
		}
	}

	// Reset all
	cmd := newMCPPinsCmd()
	cmd.SetArgs([]string{"reset", "--all"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute reset --all: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), []byte("All pins removed")) {
		t.Errorf("Expected all pins removed confirmation, got: %s", buf.String())
	}

	// Verify all pins are gone
	cmd2 := newMCPPinsCmd()
	cmd2.SetArgs([]string{"list"})
	var buf2 bytes.Buffer
	cmd2.SetOut(&buf2)

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("Execute list: %v", err)
	}

	if !bytes.Contains(buf2.Bytes(), []byte("No pins found")) {
		t.Errorf("Expected 'No pins found' after reset --all, got: %s", buf2.String())
	}
}
