package mcpinspect

import "testing"

func TestToolClassifier_ReadCategory(t *testing.T) {
	c := NewToolClassifier()

	tools := []string{
		"read_file",
		"get_user",
		"query_database",
		"list_files",
		"fetch_url",
		"search_docs",
		"find_records",
		"lookup_key",
	}

	for _, tool := range tools {
		got := c.Classify(tool)
		if got != CategoryRead {
			t.Errorf("Classify(%q) = %q, want %q", tool, got, CategoryRead)
		}
	}
}

func TestToolClassifier_WriteCategory(t *testing.T) {
	c := NewToolClassifier()

	tools := []string{
		"write_file",
		"update_record",
		"set_config",
		"create_user",
		"delete_item",
		"remove_entry",
		"put_object",
		"insert_row",
	}

	for _, tool := range tools {
		got := c.Classify(tool)
		if got != CategoryWrite {
			t.Errorf("Classify(%q) = %q, want %q", tool, got, CategoryWrite)
		}
	}
}

func TestToolClassifier_SendCategory(t *testing.T) {
	c := NewToolClassifier()

	tools := []string{
		"send_email",
		"post_message",
		"upload_file",
		"http_request",
		"email_user",
		"notify_admin",
		"publish_event",
		"push_notification",
	}

	for _, tool := range tools {
		got := c.Classify(tool)
		if got != CategorySend {
			t.Errorf("Classify(%q) = %q, want %q", tool, got, CategorySend)
		}
	}
}

func TestToolClassifier_ComputeCategory(t *testing.T) {
	c := NewToolClassifier()

	tools := []string{
		"run_command",
		"exec_shell",
		"eval_expression",
		"execute_query",
		"invoke_function",
		"call_api",
	}

	for _, tool := range tools {
		got := c.Classify(tool)
		if got != CategoryCompute {
			t.Errorf("Classify(%q) = %q, want %q", tool, got, CategoryCompute)
		}
	}
}

func TestToolClassifier_Unknown(t *testing.T) {
	c := NewToolClassifier()

	tools := []string{
		"my_custom_tool",
		"do_something",
		"transform_data",
		"analyze_code",
		"foobar",
	}

	for _, tool := range tools {
		got := c.Classify(tool)
		if got != CategoryUnknown {
			t.Errorf("Classify(%q) = %q, want %q", tool, got, CategoryUnknown)
		}
	}
}

func TestToolClassifier_EmptyString(t *testing.T) {
	c := NewToolClassifier()

	got := c.Classify("")
	if got != CategoryUnknown {
		t.Errorf("Classify(%q) = %q, want %q", "", got, CategoryUnknown)
	}
}

func TestToolClassifier_ExactPrefixNoUnderscore(t *testing.T) {
	c := NewToolClassifier()

	// "get" without trailing underscore should NOT match "get_" prefix
	tools := []string{
		"get",
		"read",
		"send",
		"run",
		"write",
	}

	for _, tool := range tools {
		got := c.Classify(tool)
		if got != CategoryUnknown {
			t.Errorf("Classify(%q) = %q, want %q (bare prefix without underscore should be unknown)", tool, got, CategoryUnknown)
		}
	}
}

func TestToolClassifier_CaseInsensitive(t *testing.T) {
	c := NewToolClassifier()

	tests := []struct {
		tool     string
		wantCat  string
	}{
		{"Read_File", CategoryRead},
		{"GET_USER", CategoryRead},
		{"Send_Email", CategorySend},
		{"WRITE_FILE", CategoryWrite},
		{"RUN_COMMAND", CategoryCompute},
	}

	for _, tt := range tests {
		got := c.Classify(tt.tool)
		if got != tt.wantCat {
			t.Errorf("Classify(%q) = %q, want %q", tt.tool, got, tt.wantCat)
		}
	}
}

func TestNewToolClassifier(t *testing.T) {
	c := NewToolClassifier()
	if c == nil {
		t.Fatal("NewToolClassifier returned nil")
	}
	if len(c.prefixes) == 0 {
		t.Error("NewToolClassifier should have default prefixes")
	}
}
