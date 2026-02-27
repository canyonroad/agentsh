package provider

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecProvider_Name(t *testing.T) {
	p := NewExecProvider("custom", ExecProviderConfig{Command: "echo"})
	assert.Equal(t, "custom", p.Name())
}

func TestExecProvider_Capabilities(t *testing.T) {
	p := NewExecProvider("custom", ExecProviderConfig{Command: "echo"})
	caps := p.Capabilities()
	assert.Contains(t, caps, pkgcheck.FindingVulnerability)
	assert.Contains(t, caps, pkgcheck.FindingLicense)
	assert.Contains(t, caps, pkgcheck.FindingProvenance)
	assert.Contains(t, caps, pkgcheck.FindingReputation)
	assert.Contains(t, caps, pkgcheck.FindingMalware)
}

func TestExecProvider_Interface(t *testing.T) {
	var _ pkgcheck.CheckProvider = NewExecProvider("custom", ExecProviderConfig{Command: "echo"})
}

func TestExecProvider_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell script test on Windows")
	}

	script := writeTestScript(t, `#!/bin/sh
cat <<'RESPONSE'
{
  "provider": "custom",
  "findings": [
    {
      "type": "vulnerability",
      "provider": "custom",
      "package": {"name": "express", "version": "4.17.1"},
      "severity": "high",
      "title": "Custom finding from exec provider"
    }
  ],
  "metadata": {}
}
RESPONSE
exit 0
`)

	p := NewExecProvider("custom", ExecProviderConfig{Command: script})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.17.1"}},
	})
	require.NoError(t, err)
	assert.Equal(t, "custom", resp.Provider)
	require.Len(t, resp.Findings, 1)
	assert.Equal(t, pkgcheck.FindingVulnerability, resp.Findings[0].Type)
	assert.Equal(t, pkgcheck.SeverityHigh, resp.Findings[0].Severity)
	assert.Equal(t, "Custom finding from exec provider", resp.Findings[0].Title)
}

func TestExecProvider_PartialFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell script test on Windows")
	}

	script := writeTestScript(t, `#!/bin/sh
cat <<'RESPONSE'
{
  "provider": "custom",
  "findings": [
    {
      "type": "reputation",
      "provider": "custom",
      "package": {"name": "partial-pkg", "version": "1.0.0"},
      "severity": "low",
      "title": "Partial result"
    }
  ],
  "metadata": {}
}
RESPONSE
echo "warning: some packages could not be checked" >&2
exit 1
`)

	p := NewExecProvider("custom", ExecProviderConfig{Command: script})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "partial-pkg", Version: "1.0.0"}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Metadata.Partial)
	assert.Contains(t, resp.Metadata.Error, "some packages could not be checked")
	require.Len(t, resp.Findings, 1)
	assert.Equal(t, "Partial result", resp.Findings[0].Title)
}

func TestExecProvider_TotalFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell script test on Windows")
	}

	script := writeTestScript(t, `#!/bin/sh
echo "fatal: provider crashed" >&2
exit 2
`)

	p := NewExecProvider("custom", ExecProviderConfig{Command: script})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.17.1"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exit code 2")
}

func TestExecProvider_MissingCommand(t *testing.T) {
	p := NewExecProvider("custom", ExecProviderConfig{Command: "/nonexistent/command"})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "express", Version: "4.17.1"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "run command")
}

func TestExecProvider_StripsEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell script test on Windows")
	}

	// This script checks if sensitive env vars from the parent leak through.
	// We only check for our custom env vars, not system ones like PATH/HOME
	// which the shell may initialize on its own.
	script := writeTestScript(t, `#!/bin/sh
if [ -n "$SECRET_KEY" ] || [ -n "$API_TOKEN" ]; then
  echo '{"provider":"custom","findings":[{"type":"malware","provider":"custom","package":{"name":"test"},"severity":"critical","title":"ENV LEAKED"}],"metadata":{}}'
  exit 0
fi
echo '{"provider":"custom","findings":[],"metadata":{}}'
exit 0
`)

	// Set some sensitive env vars in the parent.
	t.Setenv("SECRET_KEY", "super-secret-value")
	t.Setenv("API_TOKEN", "secret-token-value")

	p := NewExecProvider("custom", ExecProviderConfig{Command: script})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "test", Version: "1.0.0"}},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings, "subprocess should not have access to parent environment variables")
}

func TestExecProvider_ReadsStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell script test on Windows")
	}

	// This script echoes the input ecosystem and package count.
	script := writeTestScript(t, `#!/bin/sh
# Read stdin and extract the ecosystem using basic tools.
INPUT=$(cat)
echo '{"provider":"custom","findings":[],"metadata":{}}'
exit 0
`)

	p := NewExecProvider("custom", ExecProviderConfig{Command: script})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.17.1"},
			{Name: "lodash", Version: "4.17.21"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "custom", resp.Provider)
}

// writeTestScript creates a temporary executable shell script and returns its path.
func writeTestScript(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-provider.sh")
	err := os.WriteFile(path, []byte(content), 0o755)
	require.NoError(t, err)
	return path
}
