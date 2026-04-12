//go:build linux && cgo

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsYamaActive_WhenPresent(t *testing.T) {
	dir := t.TempDir()
	fakePath := filepath.Join(dir, "ptrace_scope")
	require.NoError(t, os.WriteFile(fakePath, []byte("1\n"), 0644))

	orig := yamaPtraceScopePath
	yamaPtraceScopePath = fakePath
	defer func() { yamaPtraceScopePath = orig }()

	assert.True(t, isYamaActive(), "should report Yama active when ptrace_scope file exists")
}

func TestIsYamaActive_WhenAbsent(t *testing.T) {
	orig := yamaPtraceScopePath
	yamaPtraceScopePath = "/nonexistent/path/ptrace_scope"
	defer func() { yamaPtraceScopePath = orig }()

	assert.False(t, isYamaActive(), "should report Yama inactive when ptrace_scope file is missing")
}
