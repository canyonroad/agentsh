package resolver

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataPath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "testdata", name)
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(testdataPath(name))
	require.NoError(t, err)
	return data
}

// --- Registry tests ---

func TestRegistry_Find(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewNPMResolver(NPMResolverConfig{}))
	reg.Register(NewPipResolver(PipResolverConfig{}))
	reg.Register(NewUVResolver(UVResolverConfig{}))

	tests := []struct {
		name    string
		command string
		args    []string
		want    string // expected resolver Name() or "" for nil
	}{
		{"npm install", "npm", []string{"install", "express"}, "npm"},
		{"pip install", "pip", []string{"install", "requests"}, "pip"},
		{"uv pip install", "uv", []string{"pip", "install", "flask"}, "uv"},
		{"unknown tool", "cargo", []string{"install", "ripgrep"}, ""},
		{"npm run", "npm", []string{"run", "build"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := reg.Find(tt.command, tt.args)
			if tt.want == "" {
				assert.Nil(t, res)
			} else {
				require.NotNil(t, res)
				assert.Equal(t, tt.want, res.Name())
			}
		})
	}
}

func TestRegistry_Empty(t *testing.T) {
	reg := NewRegistry()
	assert.Nil(t, reg.Find("npm", []string{"install", "express"}))
}

func TestRegistry_FirstMatchWins(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewNPMResolver(NPMResolverConfig{}))
	reg.Register(NewNPMResolver(NPMResolverConfig{})) // duplicate

	res := reg.Find("npm", []string{"install", "express"})
	require.NotNil(t, res)
	assert.Equal(t, "npm", res.Name())
}

// --- NPM resolver tests ---

func TestNPMResolver_CanResolve(t *testing.T) {
	r := NewNPMResolver(NPMResolverConfig{})

	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{"npm install", "npm", []string{"install", "express"}, true},
		{"npm i", "npm", []string{"i", "lodash"}, true},
		{"npm add", "npm", []string{"add", "react"}, true},
		{"npm install no args", "npm", []string{"install"}, true},
		{"npm ci", "npm", []string{"ci"}, false},
		{"npm run", "npm", []string{"run", "build"}, false},
		{"npm test", "npm", []string{"test"}, false},
		{"empty args", "npm", nil, false},
		{"full path", "/usr/local/bin/npm", []string{"install", "express"}, true},
		{"windows path", "npm.exe", []string{"install", "express"}, true},
		{"not npm", "pip", []string{"install", "requests"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.CanResolve(tt.command, tt.args))
		})
	}
}

func TestNPMResolver_Name(t *testing.T) {
	r := NewNPMResolver(NPMResolverConfig{})
	assert.Equal(t, "npm", r.Name())
}

func TestParseNPMDryRunOutput(t *testing.T) {
	data := readTestdata(t, "npm_dry_run.json")
	plan, err := parseNPMDryRunOutput(data, []string{"express"})

	require.NoError(t, err)
	assert.Equal(t, "npm", plan.Tool)
	assert.Equal(t, pkgcheck.EcosystemNPM, plan.Ecosystem)

	// express is direct
	require.Len(t, plan.Direct, 1)
	assert.Equal(t, "express", plan.Direct[0].Name)
	assert.Equal(t, "4.18.2", plan.Direct[0].Version)
	assert.True(t, plan.Direct[0].Direct)

	// accepts, body-parser, content-disposition, cookie are transitive
	assert.Len(t, plan.Transitive, 4)
	assert.Equal(t, "accepts", plan.Transitive[0].Name)
}

func TestParseNPMDryRunOutput_MultipleDirectPackages(t *testing.T) {
	data := readTestdata(t, "npm_dry_run.json")
	plan, err := parseNPMDryRunOutput(data, []string{"express", "accepts"})

	require.NoError(t, err)
	assert.Len(t, plan.Direct, 2)
	assert.Len(t, plan.Transitive, 3)
}

func TestParseNPMDryRunOutput_InvalidJSON(t *testing.T) {
	_, err := parseNPMDryRunOutput([]byte("not json"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse npm JSON output")
}

func TestParseNPMDryRunOutput_EmptyAdded(t *testing.T) {
	plan, err := parseNPMDryRunOutput([]byte(`{"added":[]}`), []string{"express"})
	require.NoError(t, err)
	assert.Empty(t, plan.Direct)
	assert.Empty(t, plan.Transitive)
}

// --- Pip resolver tests ---

func TestPipResolver_CanResolve(t *testing.T) {
	r := NewPipResolver(PipResolverConfig{})

	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{"pip install", "pip", []string{"install", "requests"}, true},
		{"pip3 install", "pip3", []string{"install", "flask"}, true},
		{"pip install no args", "pip", []string{"install"}, true},
		{"pip freeze", "pip", []string{"freeze"}, false},
		{"pip list", "pip", []string{"list"}, false},
		{"empty args", "pip", nil, false},
		{"full path", "/usr/bin/pip3", []string{"install", "requests"}, true},
		{"pip.exe", "pip.exe", []string{"install", "requests"}, true},
		{"not pip", "npm", []string{"install", "express"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.CanResolve(tt.command, tt.args))
		})
	}
}

func TestPipResolver_Name(t *testing.T) {
	r := NewPipResolver(PipResolverConfig{})
	assert.Equal(t, "pip", r.Name())
}

func TestParsePipDryRunOutput(t *testing.T) {
	data := readTestdata(t, "pip_report.json")
	plan, err := parsePipDryRunOutput(data, []string{"flask"})

	require.NoError(t, err)
	assert.Equal(t, "pip", plan.Tool)
	assert.Equal(t, pkgcheck.EcosystemPyPI, plan.Ecosystem)

	// flask is direct (has requested=true in the fixture)
	require.Len(t, plan.Direct, 1)
	assert.Equal(t, "flask", plan.Direct[0].Name)
	assert.Equal(t, "3.0.0", plan.Direct[0].Version)
	assert.True(t, plan.Direct[0].Direct)

	// Werkzeug, Jinja2, MarkupSafe, itsdangerous are transitive
	assert.Len(t, plan.Transitive, 4)
}

func TestParsePipDryRunOutput_CaseInsensitiveMatch(t *testing.T) {
	// pip package names are case-insensitive
	data := readTestdata(t, "pip_report.json")
	plan, err := parsePipDryRunOutput(data, []string{"Flask"})

	require.NoError(t, err)
	// flask should be matched case-insensitively via both "requested" flag and name
	assert.Len(t, plan.Direct, 1)
	assert.Equal(t, "flask", plan.Direct[0].Name)
}

func TestParsePipDryRunOutput_InvalidJSON(t *testing.T) {
	_, err := parsePipDryRunOutput([]byte("not json"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse pip report JSON")
}

func TestParsePipDryRunOutput_EmptyInstall(t *testing.T) {
	plan, err := parsePipDryRunOutput([]byte(`{"install":[]}`), []string{"flask"})
	require.NoError(t, err)
	assert.Empty(t, plan.Direct)
	assert.Empty(t, plan.Transitive)
}

// --- UV resolver tests ---

func TestUVResolver_CanResolve(t *testing.T) {
	r := NewUVResolver(UVResolverConfig{})

	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{"uv pip install", "uv", []string{"pip", "install", "flask"}, true},
		{"uv add", "uv", []string{"add", "flask"}, true},
		{"uv pip install no args", "uv", []string{"pip", "install"}, true},
		{"uv run", "uv", []string{"run", "script.py"}, false},
		{"uv pip only", "uv", []string{"pip"}, false},
		{"empty args", "uv", nil, false},
		{"full path", "/usr/local/bin/uv", []string{"pip", "install", "flask"}, true},
		{"uv.exe", "uv.exe", []string{"add", "flask"}, true},
		{"not uv", "npm", []string{"install", "express"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.CanResolve(tt.command, tt.args))
		})
	}
}

func TestUVResolver_Name(t *testing.T) {
	r := NewUVResolver(UVResolverConfig{})
	assert.Equal(t, "uv", r.Name())
}

func TestParseUVDryRunOutput(t *testing.T) {
	data := readTestdata(t, "uv_dry_run.txt")
	plan, err := parseUVDryRunOutput(data, []string{"flask"})

	require.NoError(t, err)
	assert.Equal(t, "uv", plan.Tool)
	assert.Equal(t, pkgcheck.EcosystemPyPI, plan.Ecosystem)

	// flask is direct
	require.Len(t, plan.Direct, 1)
	assert.Equal(t, "flask", plan.Direct[0].Name)
	assert.Equal(t, "3.0.0", plan.Direct[0].Version)
	assert.True(t, plan.Direct[0].Direct)

	// werkzeug, jinja2, markupsafe, itsdangerous are transitive
	assert.Len(t, plan.Transitive, 4)
}

func TestParseUVDryRunOutput_EmptyOutput(t *testing.T) {
	plan, err := parseUVDryRunOutput([]byte(""), []string{"flask"})
	require.NoError(t, err)
	assert.Empty(t, plan.Direct)
	assert.Empty(t, plan.Transitive)
}

func TestParseUVDryRunOutput_MultipleDirectPackages(t *testing.T) {
	output := "Would install flask-3.0.0 requests-2.31.0 urllib3-2.1.0\n"
	plan, err := parseUVDryRunOutput([]byte(output), []string{"flask", "requests"})

	require.NoError(t, err)
	assert.Len(t, plan.Direct, 2)
	assert.Len(t, plan.Transitive, 1)

	// Check direct packages
	directNames := make(map[string]bool)
	for _, d := range plan.Direct {
		directNames[d.Name] = true
	}
	assert.True(t, directNames["flask"])
	assert.True(t, directNames["requests"])
}

func TestParseUVPackageSpec(t *testing.T) {
	tests := []struct {
		spec    string
		name    string
		version string
	}{
		{"flask-3.0.0", "flask", "3.0.0"},
		{"markupsafe-2.1.3", "markupsafe", "2.1.3"},
		{"Jinja2-3.1.2", "Jinja2", "3.1.2"},
		{"my-cool-package-1.0.0", "my-cool-package", "1.0.0"},
		{"flask", "flask", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			name, version := parseUVPackageSpec(tt.spec)
			assert.Equal(t, tt.name, name)
			assert.Equal(t, tt.version, version)
		})
	}
}

// --- PNPM resolver tests ---

func TestPNPMResolver_CanResolve(t *testing.T) {
	r := NewPNPMResolver(PNPMResolverConfig{})

	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{"pnpm add", "pnpm", []string{"add", "react"}, true},
		{"pnpm install", "pnpm", []string{"install"}, true},
		{"pnpm i", "pnpm", []string{"i"}, true},
		{"pnpm run", "pnpm", []string{"run", "test"}, false},
		{"empty args", "pnpm", nil, false},
		{"full path", "/usr/local/bin/pnpm", []string{"add", "react"}, true},
		{"pnpm.exe", "pnpm.exe", []string{"add", "react"}, true},
		{"not pnpm", "npm", []string{"install", "express"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.CanResolve(tt.command, tt.args))
		})
	}
}

func TestPNPMResolver_Name(t *testing.T) {
	r := NewPNPMResolver(PNPMResolverConfig{})
	assert.Equal(t, "pnpm", r.Name())
}

func TestParsePNPMDryRunOutput(t *testing.T) {
	data := readTestdata(t, "pnpm_dry_run.json")
	plan, err := parsePNPMDryRunOutput(data, []string{"react", "react-dom"})

	require.NoError(t, err)
	assert.Equal(t, "pnpm", plan.Tool)
	assert.Equal(t, pkgcheck.EcosystemNPM, plan.Ecosystem)

	// react and react-dom are direct
	require.Len(t, plan.Direct, 2)
	directNames := make(map[string]bool)
	for _, d := range plan.Direct {
		directNames[d.Name] = true
		assert.True(t, d.Direct)
	}
	assert.True(t, directNames["react"])
	assert.True(t, directNames["react-dom"])

	// js-tokens, loose-envify, scheduler are transitive
	assert.Len(t, plan.Transitive, 3)
}

func TestParsePNPMDryRunOutput_InvalidJSON(t *testing.T) {
	_, err := parsePNPMDryRunOutput([]byte("not json"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse pnpm JSON output")
}

// --- Yarn resolver tests ---

func TestYarnResolver_CanResolve(t *testing.T) {
	r := NewYarnResolver(YarnResolverConfig{})

	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{"yarn add", "yarn", []string{"add", "typescript"}, true},
		{"yarn install", "yarn", []string{"install"}, true},
		{"yarn test", "yarn", []string{"test"}, false},
		{"yarn run", "yarn", []string{"run", "build"}, false},
		{"empty args", "yarn", nil, false},
		{"full path", "/usr/local/bin/yarn", []string{"add", "react"}, true},
		{"yarn.exe", "yarn.exe", []string{"add", "react"}, true},
		{"not yarn", "npm", []string{"install", "express"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.CanResolve(tt.command, tt.args))
		})
	}
}

func TestYarnResolver_Name(t *testing.T) {
	r := NewYarnResolver(YarnResolverConfig{})
	assert.Equal(t, "yarn", r.Name())
}

func TestParseYarnDryRunOutput(t *testing.T) {
	data := readTestdata(t, "yarn_dry_run.json")
	plan, err := parseYarnDryRunOutput(data, []string{"typescript"})

	require.NoError(t, err)
	assert.Equal(t, "yarn", plan.Tool)
	assert.Equal(t, pkgcheck.EcosystemNPM, plan.Ecosystem)

	require.Len(t, plan.Direct, 1)
	assert.Equal(t, "typescript", plan.Direct[0].Name)
	assert.Equal(t, "5.3.3", plan.Direct[0].Version)
	assert.True(t, plan.Direct[0].Direct)

	assert.Empty(t, plan.Transitive)
}

func TestParseYarnDryRunOutput_InvalidJSON(t *testing.T) {
	_, err := parseYarnDryRunOutput([]byte("not json"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse yarn JSON output")
}

// --- Poetry resolver tests ---

func TestPoetryResolver_CanResolve(t *testing.T) {
	r := NewPoetryResolver(PoetryResolverConfig{})

	tests := []struct {
		name    string
		command string
		args    []string
		want    bool
	}{
		{"poetry add", "poetry", []string{"add", "django"}, true},
		{"poetry install", "poetry", []string{"install"}, true},
		{"poetry build", "poetry", []string{"build"}, false},
		{"poetry publish", "poetry", []string{"publish"}, false},
		{"empty args", "poetry", nil, false},
		{"full path", "/usr/local/bin/poetry", []string{"add", "django"}, true},
		{"poetry.exe", "poetry.exe", []string{"add", "django"}, true},
		{"not poetry", "pip", []string{"install", "requests"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.CanResolve(tt.command, tt.args))
		})
	}
}

func TestPoetryResolver_Name(t *testing.T) {
	r := NewPoetryResolver(PoetryResolverConfig{})
	assert.Equal(t, "poetry", r.Name())
}

func TestParsePoetryDryRunOutput(t *testing.T) {
	data := readTestdata(t, "poetry_dry_run.json")
	plan, err := parsePoetryDryRunOutput(data, []string{"django"})

	require.NoError(t, err)
	assert.Equal(t, "poetry", plan.Tool)
	assert.Equal(t, pkgcheck.EcosystemPyPI, plan.Ecosystem)

	// django is direct
	require.Len(t, plan.Direct, 1)
	assert.Equal(t, "django", plan.Direct[0].Name)
	assert.Equal(t, "5.0.1", plan.Direct[0].Version)
	assert.True(t, plan.Direct[0].Direct)

	// asgiref, sqlparse are transitive
	assert.Len(t, plan.Transitive, 2)
}

func TestParsePoetryDryRunOutput_CaseInsensitive(t *testing.T) {
	data := readTestdata(t, "poetry_dry_run.json")
	plan, err := parsePoetryDryRunOutput(data, []string{"Django"})

	require.NoError(t, err)
	// django should match case-insensitively
	assert.Len(t, plan.Direct, 1)
	assert.Equal(t, "django", plan.Direct[0].Name)
}

func TestParsePoetryDryRunOutput_InvalidJSON(t *testing.T) {
	_, err := parsePoetryDryRunOutput([]byte("not json"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse poetry JSON output")
}

// --- Shared helper tests ---

func TestPkgBaseName(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"express", "express"},
		{"express@4.18.0", "express"},
		{"@types/node", "@types/node"},
		{"@types/node@20.0.0", "@types/node"},
		{"requests>=2.28.0", "requests"},
		{"flask~=3.0.0", "flask"},
		{"django==5.0.1", "django"},
		{"numpy!=1.24.0", "numpy"},
		{"pandas>2.0", "pandas"},
		{"scipy<2.0.0", "scipy"},
		{"torch<=2.1.0", "torch"},
		{"@babel/core@7.23.0", "@babel/core"},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			assert.Equal(t, tt.want, pkgBaseName(tt.spec))
		})
	}
}

func TestExtractPkgArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "simple packages after subcommand",
			args: []string{"install", "express", "lodash"},
			want: []string{"express", "lodash"},
		},
		{
			name: "packages with flags mixed in",
			args: []string{"install", "--save-dev", "express"},
			want: []string{"express"},
		},
		{
			name: "flag with value",
			args: []string{"install", "--registry", "https://example.com", "express"},
			want: []string{"express"},
		},
		{
			name: "flag with equals",
			args: []string{"install", "--registry=https://example.com", "express"},
			want: []string{"express"},
		},
		{
			name: "add subcommand",
			args: []string{"add", "react", "react-dom"},
			want: []string{"react", "react-dom"},
		},
		{
			name: "empty args",
			args: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPkgArgs(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- Interface compliance tests ---

func TestNPMResolver_ImplementsInterface(t *testing.T) {
	var _ pkgcheck.Resolver = NewNPMResolver(NPMResolverConfig{})
}

func TestPipResolver_ImplementsInterface(t *testing.T) {
	var _ pkgcheck.Resolver = NewPipResolver(PipResolverConfig{})
}

func TestUVResolver_ImplementsInterface(t *testing.T) {
	var _ pkgcheck.Resolver = NewUVResolver(UVResolverConfig{})
}

func TestPNPMResolver_ImplementsInterface(t *testing.T) {
	var _ pkgcheck.Resolver = NewPNPMResolver(PNPMResolverConfig{})
}

func TestYarnResolver_ImplementsInterface(t *testing.T) {
	var _ pkgcheck.Resolver = NewYarnResolver(YarnResolverConfig{})
}

func TestPoetryResolver_ImplementsInterface(t *testing.T) {
	var _ pkgcheck.Resolver = NewPoetryResolver(PoetryResolverConfig{})
}

// --- Default config tests ---

func TestNPMResolver_DefaultConfig(t *testing.T) {
	r := NewNPMResolver(NPMResolverConfig{}).(*npmResolver)
	assert.Equal(t, "npm", r.cfg.DryRunCommand)
	assert.Equal(t, 30*time.Second, r.cfg.Timeout)
}

func TestPipResolver_DefaultConfig(t *testing.T) {
	r := NewPipResolver(PipResolverConfig{}).(*pipResolver)
	assert.Equal(t, "pip", r.cfg.DryRunCommand)
	assert.Equal(t, 30*time.Second, r.cfg.Timeout)
}

func TestUVResolver_DefaultConfig(t *testing.T) {
	r := NewUVResolver(UVResolverConfig{}).(*uvResolver)
	assert.Equal(t, "uv", r.cfg.DryRunCommand)
	assert.Equal(t, 30*time.Second, r.cfg.Timeout)
}

func TestPNPMResolver_DefaultConfig(t *testing.T) {
	r := NewPNPMResolver(PNPMResolverConfig{}).(*pnpmResolver)
	assert.Equal(t, "pnpm", r.cfg.DryRunCommand)
	assert.Equal(t, 30*time.Second, r.cfg.Timeout)
}

func TestYarnResolver_DefaultConfig(t *testing.T) {
	r := NewYarnResolver(YarnResolverConfig{}).(*yarnResolver)
	assert.Equal(t, "yarn", r.cfg.DryRunCommand)
	assert.Equal(t, 30*time.Second, r.cfg.Timeout)
}

func TestPoetryResolver_DefaultConfig(t *testing.T) {
	r := NewPoetryResolver(PoetryResolverConfig{}).(*poetryResolver)
	assert.Equal(t, "poetry", r.cfg.DryRunCommand)
	assert.Equal(t, 30*time.Second, r.cfg.Timeout)
}

// --- Custom config tests ---

func TestNPMResolver_CustomConfig(t *testing.T) {
	r := NewNPMResolver(NPMResolverConfig{
		DryRunCommand: "/custom/npm",
		Timeout:       60 * time.Second,
	}).(*npmResolver)
	assert.Equal(t, "/custom/npm", r.cfg.DryRunCommand)
	assert.Equal(t, 60*time.Second, r.cfg.Timeout)
}
