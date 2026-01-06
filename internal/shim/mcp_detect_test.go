// internal/shim/mcp_detect_test.go
package shim

import "testing"

func TestIsMCPServer_DefaultPatterns(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		args []string
		want bool
	}{
		{
			name: "npx modelcontextprotocol server",
			cmd:  "npx",
			args: []string{"@modelcontextprotocol/server-filesystem", "/workspace"},
			want: true,
		},
		{
			name: "mcp-server- prefix",
			cmd:  "mcp-server-sqlite",
			args: []string{"--db", "test.db"},
			want: true,
		},
		{
			name: "suffix -mcp-server",
			cmd:  "custom-mcp-server",
			args: []string{},
			want: true,
		},
		{
			name: "python mcp_server",
			cmd:  "python",
			args: []string{"-m", "mcp_server_fetch"},
			want: true,
		},
		{
			name: "uvx mcp-server",
			cmd:  "uvx",
			args: []string{"mcp-server-git", "--repo", "."},
			want: true,
		},
		{
			name: "regular command",
			cmd:  "ls",
			args: []string{"-la"},
			want: false,
		},
		{
			name: "git command",
			cmd:  "git",
			args: []string{"status"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMCPServer(tt.cmd, tt.args, nil)
			if got != tt.want {
				t.Errorf("IsMCPServer(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}

func TestIsMCPServer_CustomPatterns(t *testing.T) {
	custom := []string{"my-company-mcp-*", "internal-*-mcp"}

	tests := []struct {
		name string
		cmd  string
		args []string
		want bool
	}{
		{
			name: "custom pattern match",
			cmd:  "my-company-mcp-tools",
			args: []string{},
			want: true,
		},
		{
			name: "custom suffix pattern",
			cmd:  "internal-data-mcp",
			args: []string{},
			want: true,
		},
		{
			name: "no match",
			cmd:  "other-tool",
			args: []string{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsMCPServer(tt.cmd, tt.args, custom)
			if got != tt.want {
				t.Errorf("IsMCPServer(%q, %v, custom) = %v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}
