package mcpinspect

import "strings"

// Tool categories used by the cross-server pattern detector.
const (
	CategoryRead    = "read"
	CategoryWrite   = "write"
	CategorySend    = "send"
	CategoryCompute = "compute"
	CategoryUnknown = "unknown"
)

// defaultPrefixes maps tool name prefixes to their categories.
// A tool matches a category if its name starts with one of these prefixes.
var defaultPrefixes = []struct {
	prefix   string
	category string
}{
	// read
	{"read_", CategoryRead},
	{"get_", CategoryRead},
	{"query_", CategoryRead},
	{"list_", CategoryRead},
	{"fetch_", CategoryRead},
	{"search_", CategoryRead},
	{"find_", CategoryRead},
	{"lookup_", CategoryRead},

	// write
	{"write_", CategoryWrite},
	{"update_", CategoryWrite},
	{"set_", CategoryWrite},
	{"create_", CategoryWrite},
	{"delete_", CategoryWrite},
	{"remove_", CategoryWrite},
	{"put_", CategoryWrite},
	{"insert_", CategoryWrite},

	// send
	{"send_", CategorySend},
	{"post_", CategorySend},
	{"upload_", CategorySend},
	{"http_", CategorySend},
	{"email_", CategorySend},
	{"notify_", CategorySend},
	{"publish_", CategorySend},
	{"push_", CategorySend},

	// compute
	{"run_", CategoryCompute},
	{"exec_", CategoryCompute},
	{"eval_", CategoryCompute},
	{"execute_", CategoryCompute},
	{"invoke_", CategoryCompute},
	{"call_", CategoryCompute},
}

// ToolClassifier categorises MCP tool names into semantic buckets
// (read, write, send, compute, unknown) using prefix matching.
type ToolClassifier struct {
	prefixes []struct {
		prefix   string
		category string
	}
}

// NewToolClassifier returns a classifier using the default prefix table.
func NewToolClassifier() *ToolClassifier {
	return &ToolClassifier{prefixes: defaultPrefixes}
}

// Classify returns the category for the given tool name.
// It uses simple prefix matching against the known patterns.
// Tools that don't match any pattern return "unknown".
func (c *ToolClassifier) Classify(toolName string) string {
	lower := strings.ToLower(toolName)
	for _, p := range c.prefixes {
		if strings.HasPrefix(lower, p.prefix) {
			return p.category
		}
	}
	return CategoryUnknown
}
