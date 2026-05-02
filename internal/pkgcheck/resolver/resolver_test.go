package resolver

import (
	"os"
	"path/filepath"
	"reflect"
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
		{"npm.cmd", "npm.cmd", []string{"install", "express"}, true},
		{"mixed case NPM.EXE", "NPM.EXE", []string{"install", "express"}, true},
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
		{"mixed case PIP3.CMD", "PIP3.CMD", []string{"install", "requests"}, true},
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
		{"uv add not supported by resolver", "uv", []string{"add", "flask"}, false},
		{"uv pip install no args", "uv", []string{"pip", "install"}, true},
		{"uv run", "uv", []string{"run", "script.py"}, false},
		{"uv pip only", "uv", []string{"pip"}, false},
		{"empty args", "uv", nil, false},
		{"full path", "/usr/local/bin/uv", []string{"pip", "install", "flask"}, true},
		{"uv.exe", "uv.exe", []string{"pip", "install", "flask"}, true},
		{"mixed case UV.EXE", "UV.EXE", []string{"pip", "install", "flask"}, true},
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
		{"pnpm.cmd", "pnpm.cmd", []string{"add", "react"}, true},
		{"mixed case Pnpm.Cmd", "Pnpm.Cmd", []string{"add", "react"}, true},
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
		{"yarn install not supported by resolver", "yarn", []string{"install"}, false},
		{"yarn test", "yarn", []string{"test"}, false},
		{"yarn run", "yarn", []string{"run", "build"}, false},
		{"empty args", "yarn", nil, false},
		{"full path", "/usr/local/bin/yarn", []string{"add", "react"}, true},
		{"yarn.exe", "yarn.exe", []string{"add", "react"}, true},
		{"yarn.cmd", "yarn.cmd", []string{"add", "react"}, true},
		{"mixed case YARN.BAT", "YARN.BAT", []string{"add", "react"}, true},
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
		{"poetry install not supported by resolver", "poetry", []string{"install"}, false},
		{"poetry build", "poetry", []string{"build"}, false},
		{"poetry publish", "poetry", []string{"publish"}, false},
		{"empty args", "poetry", nil, false},
		{"full path", "/usr/local/bin/poetry", []string{"add", "django"}, true},
		{"poetry.exe", "poetry.exe", []string{"add", "django"}, true},
		{"mixed case Poetry.Cmd", "Poetry.Cmd", []string{"add", "django"}, true},
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

// --- Registry field tests ---

func TestNPMResolver_PlanCarriesRegistry(t *testing.T) {
	plan, err := parseNPMDryRunOutput([]byte(`{"added":[{"name":"express","version":"4.18.2"}]}`), []string{"express"})
	require.NoError(t, err)
	assert.Equal(t, "registry.npmjs.org", plan.Registry)
}

func TestPipResolver_PlanCarriesRegistry(t *testing.T) {
	plan, err := parsePipDryRunOutput([]byte(`{"install":[{"metadata":{"name":"flask","version":"3.0.0"},"requested":true}]}`), []string{"flask"})
	require.NoError(t, err)
	assert.Equal(t, "pypi.org", plan.Registry)
}

func TestUVResolver_PlanCarriesRegistry(t *testing.T) {
	plan, err := parseUVDryRunOutput([]byte("Would install flask-3.0.0\n"), []string{"flask"})
	require.NoError(t, err)
	assert.Equal(t, "pypi.org", plan.Registry)
}

func TestPNPMResolver_PlanCarriesRegistry(t *testing.T) {
	plan, err := parsePNPMDryRunOutput([]byte(`{"added":[{"name":"react","version":"18.2.0"}]}`), []string{"react"})
	require.NoError(t, err)
	assert.Equal(t, "registry.npmjs.org", plan.Registry)
}

func TestYarnResolver_PlanCarriesRegistry(t *testing.T) {
	plan, err := parseYarnDryRunOutput([]byte(`{"added":[{"name":"typescript","version":"5.3.3"}]}`), []string{"typescript"})
	require.NoError(t, err)
	assert.Equal(t, "registry.npmjs.org", plan.Registry)
}

func TestPoetryResolver_PlanCarriesEmptyRegistryFailClosed(t *testing.T) {
	// Poetry source registries live in pyproject.toml; we don't parse it.
	// The resolver leaves Registry empty so the privacy filter fails closed
	// — operators using public PyPI must allowlist "pypi.org" explicitly.
	plan, err := parsePoetryDryRunOutput([]byte(`{"added":[{"name":"django","version":"5.0.1"}]}`), []string{"django"})
	require.NoError(t, err)
	assert.Equal(t, "", plan.Registry)
}

// --- DryRunArgs explicit-fields tests ---

func TestNPMResolver_DryRunArgs(t *testing.T) {
	r := NewNPMResolver(NPMResolverConfig{
		DryRunCommand: "npx",
		DryRunArgs:    []string{"npm", "--prefix", "/tmp"},
	}).(*npmResolver)
	assert.Equal(t, "npx", r.binary)
	assert.Equal(t, []string{"npm", "--prefix", "/tmp"}, r.prefixArgs)
}

func TestNPMResolver_BinaryPathWithSpacesPreserved(t *testing.T) {
	r := NewNPMResolver(NPMResolverConfig{
		DryRunCommand: "/Program Files/node/npm.cmd",
		DryRunArgs:    []string{"install", "--package-lock-only"},
	}).(*npmResolver)
	assert.Equal(t, "/Program Files/node/npm.cmd", r.binary)
	assert.Equal(t, []string{"install", "--package-lock-only"}, r.prefixArgs)
}

func TestPipResolver_DryRunArgs(t *testing.T) {
	r := NewPipResolver(PipResolverConfig{
		DryRunCommand: "python",
		DryRunArgs:    []string{"-m", "pip"},
	}).(*pipResolver)
	assert.Equal(t, "python", r.binary)
	assert.Equal(t, []string{"-m", "pip"}, r.prefixArgs)
}

func TestPipResolver_BinaryPathWithSpacesPreserved(t *testing.T) {
	r := NewPipResolver(PipResolverConfig{
		DryRunCommand: "/Program Files/Python312/python.exe",
		DryRunArgs:    []string{"-m", "pip"},
	}).(*pipResolver)
	assert.Equal(t, "/Program Files/Python312/python.exe", r.binary)
	assert.Equal(t, []string{"-m", "pip"}, r.prefixArgs)
}

func TestUVResolver_DryRunArgs(t *testing.T) {
	r := NewUVResolver(UVResolverConfig{
		DryRunCommand: "/usr/local/bin/uv",
		DryRunArgs:    []string{"--quiet"},
	}).(*uvResolver)
	assert.Equal(t, "/usr/local/bin/uv", r.binary)
	assert.Equal(t, []string{"--quiet"}, r.prefixArgs)
}

func TestUVResolver_BinaryPathWithSpacesPreserved(t *testing.T) {
	r := NewUVResolver(UVResolverConfig{
		DryRunCommand: "/Program Files/uv/uv.exe",
	}).(*uvResolver)
	assert.Equal(t, "/Program Files/uv/uv.exe", r.binary)
	assert.Empty(t, r.prefixArgs)
}

func TestPNPMResolver_DryRunArgs(t *testing.T) {
	r := NewPNPMResolver(PNPMResolverConfig{
		DryRunCommand: "pnpm",
		DryRunArgs:    []string{"--store-dir", "/tmp"},
	}).(*pnpmResolver)
	assert.Equal(t, "pnpm", r.binary)
	assert.Equal(t, []string{"--store-dir", "/tmp"}, r.prefixArgs)
}

func TestPNPMResolver_BinaryPathWithSpacesPreserved(t *testing.T) {
	r := NewPNPMResolver(PNPMResolverConfig{
		DryRunCommand: "/Program Files/pnpm/pnpm.cmd",
	}).(*pnpmResolver)
	assert.Equal(t, "/Program Files/pnpm/pnpm.cmd", r.binary)
	assert.Empty(t, r.prefixArgs)
}

func TestYarnResolver_DryRunArgs(t *testing.T) {
	r := NewYarnResolver(YarnResolverConfig{
		DryRunCommand: "yarn",
		DryRunArgs:    []string{"--cwd", "/tmp"},
	}).(*yarnResolver)
	assert.Equal(t, "yarn", r.binary)
	assert.Equal(t, []string{"--cwd", "/tmp"}, r.prefixArgs)
}

func TestYarnResolver_BinaryPathWithSpacesPreserved(t *testing.T) {
	r := NewYarnResolver(YarnResolverConfig{
		DryRunCommand: "/Program Files/yarn/bin/yarn.cmd",
	}).(*yarnResolver)
	assert.Equal(t, "/Program Files/yarn/bin/yarn.cmd", r.binary)
	assert.Empty(t, r.prefixArgs)
}

func TestPoetryResolver_DryRunArgs(t *testing.T) {
	r := NewPoetryResolver(PoetryResolverConfig{
		DryRunCommand: "poetry",
		DryRunArgs:    []string{"--no-ansi"},
	}).(*poetryResolver)
	assert.Equal(t, "poetry", r.binary)
	assert.Equal(t, []string{"--no-ansi"}, r.prefixArgs)
}

func TestPoetryResolver_BinaryPathWithSpacesPreserved(t *testing.T) {
	r := NewPoetryResolver(PoetryResolverConfig{
		DryRunCommand: "/Program Files/poetry/poetry.exe",
	}).(*poetryResolver)
	assert.Equal(t, "/Program Files/poetry/poetry.exe", r.binary)
	assert.Empty(t, r.prefixArgs)
}

// --- Registry detection tests ---

func TestNPMResolver_DetectRegistry(t *testing.T) {
	r := &npmResolver{}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default (no flag)", []string{"install", "lodash"}, "registry.npmjs.org"},
		{"--registry space", []string{"install", "--registry", "https://internal.example/"}, "https://internal.example/"},
		{"--registry=", []string{"install", "--registry=https://x/"}, "https://x/"},
		{"--registry last", []string{"--registry", "https://r/"}, "https://r/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.detectRegistry(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPNPMResolver_DetectRegistry(t *testing.T) {
	r := &pnpmResolver{}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default", []string{"add", "react"}, "registry.npmjs.org"},
		{"--registry space", []string{"add", "--registry", "https://internal.example/"}, "https://internal.example/"},
		{"--registry=", []string{"add", "--registry=https://x/"}, "https://x/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.detectRegistry(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestYarnResolver_DetectRegistry(t *testing.T) {
	r := &yarnResolver{}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default", []string{"add", "typescript"}, "registry.npmjs.org"},
		{"--registry space", []string{"add", "--registry", "https://internal.example/"}, "https://internal.example/"},
		{"--registry=", []string{"add", "--registry=https://x/"}, "https://x/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.detectRegistry(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPipResolver_DetectRegistry(t *testing.T) {
	r := &pipResolver{}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default", []string{"install", "requests"}, "pypi.org"},
		{"--index-url space", []string{"install", "--index-url", "https://internal/simple"}, "https://internal/simple"},
		{"--index-url=", []string{"install", "--index-url=https://internal/simple"}, "https://internal/simple"},
		{"-i space", []string{"install", "-i", "https://internal/simple"}, "https://internal/simple"},
		// --extra-index-url → ambiguous origin, return ""
		{"--extra-index-url space", []string{"install", "requests", "--extra-index-url", "https://internal/simple"}, ""},
		{"--extra-index-url=", []string{"install", "requests", "--extra-index-url=https://internal/simple"}, ""},
		// --index-url plus --extra-index-url → still ambiguous
		{"index-url + extra", []string{"install", "--index-url", "https://primary/", "--extra-index-url", "https://extra/"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.detectRegistry(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUVResolver_DetectRegistry(t *testing.T) {
	r := &uvResolver{}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"default", []string{"pip", "install", "flask"}, "pypi.org"},
		{"--index-url space", []string{"pip", "install", "--index-url", "https://internal/simple"}, "https://internal/simple"},
		{"--index-url=", []string{"pip", "install", "--index-url=https://internal/simple"}, "https://internal/simple"},
		// --extra-index-url → ambiguous origin, return ""
		{"--extra-index-url space", []string{"pip", "install", "flask", "--extra-index-url", "https://internal/simple"}, ""},
		{"--extra-index-url=", []string{"pip", "install", "flask", "--extra-index-url=https://internal/simple"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.detectRegistry(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- Scoped package fail-closed tests (Fix 1) ---

func TestIsScopedPackage(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"@acme/foo", true},
		{"@types/node", true},
		{"@babel/core", true},
		{"lodash", false},
		{"express", false},
		{"@missingslash", false}, // @ but no /
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isScopedPackage(tt.name))
		})
	}
}

func TestNPMResolver_HasRegistryFlag(t *testing.T) {
	r := &npmResolver{}
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"no flag", []string{"install", "@acme/foo"}, false},
		{"--registry space", []string{"install", "--registry", "https://r/"}, true},
		{"--registry=", []string{"install", "--registry=https://r/"}, true},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, r.hasRegistryFlag(tt.args))
		})
	}
}

func TestPNPMResolver_HasRegistryFlag(t *testing.T) {
	r := &pnpmResolver{}
	assert.False(t, r.hasRegistryFlag([]string{"add", "@acme/foo"}))
	assert.True(t, r.hasRegistryFlag([]string{"add", "--registry", "https://r/"}))
	assert.True(t, r.hasRegistryFlag([]string{"add", "--registry=https://r/"}))
}

func TestYarnResolver_HasRegistryFlag(t *testing.T) {
	r := &yarnResolver{}
	assert.False(t, r.hasRegistryFlag([]string{"add", "@acme/foo"}))
	assert.True(t, r.hasRegistryFlag([]string{"add", "--registry", "https://r/"}))
	assert.True(t, r.hasRegistryFlag([]string{"add", "--registry=https://r/"}))
}

// TestNPMResolver_ScopedPackageRegistryFailsClosed verifies that scoped packages
// parsed from npm dry-run output get an empty Registry when no --registry flag is
// present, while unscoped packages get the default registry.
func TestNPMResolver_ScopedPackageRegistryFailsClosed(t *testing.T) {
	json := `{"added":[
		{"name":"@acme/foo","version":"1.2.3"},
		{"name":"lodash","version":"4.17.21"}
	]}`
	plan, err := parseNPMDryRunOutput([]byte(json), []string{"@acme/foo", "lodash"})
	require.NoError(t, err)

	r := &npmResolver{}
	planRegistry := r.detectRegistry([]string{"install", "@acme/foo", "lodash"})
	explicitFlag := r.hasRegistryFlag([]string{"install", "@acme/foo", "lodash"})

	for i := range plan.Direct {
		if isScopedPackage(plan.Direct[i].Name) && !explicitFlag {
			plan.Direct[i].Registry = ""
		} else {
			plan.Direct[i].Registry = planRegistry
		}
	}

	byName := make(map[string]pkgcheck.PackageRef)
	for _, p := range plan.Direct {
		byName[p.Name] = p
	}

	// @acme/foo should have empty Registry (fail closed — could be private)
	if byName["@acme/foo"].Registry != "" {
		t.Errorf("expected empty Registry for @acme/foo, got %q", byName["@acme/foo"].Registry)
	}
	// lodash should have default registry
	if byName["lodash"].Registry != "registry.npmjs.org" {
		t.Errorf("expected registry.npmjs.org for lodash, got %q", byName["lodash"].Registry)
	}
}

// TestNPMResolver_ScopedPackageWithExplicitFlagGetsRegistry verifies that scoped
// packages DO receive the registry when --registry is explicitly set on the CLI.
func TestNPMResolver_ScopedPackageWithExplicitFlagGetsRegistry(t *testing.T) {
	json := `{"added":[{"name":"@acme/foo","version":"1.2.3"}]}`
	plan, err := parseNPMDryRunOutput([]byte(json), []string{"@acme/foo"})
	require.NoError(t, err)

	r := &npmResolver{}
	args := []string{"install", "--registry=https://internal.example/", "@acme/foo"}
	planRegistry := r.detectRegistry(args)
	explicitFlag := r.hasRegistryFlag(args)

	for i := range plan.Direct {
		if isScopedPackage(plan.Direct[i].Name) && !explicitFlag {
			plan.Direct[i].Registry = ""
		} else {
			plan.Direct[i].Registry = planRegistry
		}
	}

	if plan.Direct[0].Registry != "https://internal.example/" {
		t.Errorf("expected https://internal.example/, got %q", plan.Direct[0].Registry)
	}
}

// --- Extract registry/index-url flag tests (Fix A) ---

func TestNPMResolver_ExtractRegistryFlags(t *testing.T) {
	r := &npmResolver{}
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"install", "lodash"}, nil},
		{[]string{"install", "--registry", "https://internal/", "lodash"}, []string{"--registry", "https://internal/"}},
		{[]string{"install", "--registry=https://x/", "lodash"}, []string{"--registry=https://x/"}},
		{nil, nil},
	}
	for _, c := range cases {
		got := r.extractRegistryFlags(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("input %v: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPNPMResolver_ExtractRegistryFlags(t *testing.T) {
	r := &pnpmResolver{}
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"add", "react"}, nil},
		{[]string{"add", "--registry", "https://internal/", "react"}, []string{"--registry", "https://internal/"}},
		{[]string{"add", "--registry=https://x/", "react"}, []string{"--registry=https://x/"}},
	}
	for _, c := range cases {
		got := r.extractRegistryFlags(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("input %v: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestYarnResolver_ExtractRegistryFlags(t *testing.T) {
	r := &yarnResolver{}
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"add", "typescript"}, nil},
		{[]string{"add", "--registry", "https://internal/", "typescript"}, []string{"--registry", "https://internal/"}},
		{[]string{"add", "--registry=https://x/", "typescript"}, []string{"--registry=https://x/"}},
	}
	for _, c := range cases {
		got := r.extractRegistryFlags(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("input %v: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPipResolver_ExtractIndexURLFlags(t *testing.T) {
	r := &pipResolver{}
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"install", "requests"}, nil},
		{[]string{"install", "--index-url", "https://internal/simple", "requests"}, []string{"--index-url", "https://internal/simple"}},
		{[]string{"install", "--index-url=https://internal/simple", "requests"}, []string{"--index-url=https://internal/simple"}},
		{[]string{"install", "-i", "https://internal/simple", "requests"}, []string{"-i", "https://internal/simple"}},
		{[]string{"install", "--extra-index-url", "https://extra/simple", "requests"}, []string{"--extra-index-url", "https://extra/simple"}},
		{[]string{"install", "--extra-index-url=https://extra/simple", "requests"}, []string{"--extra-index-url=https://extra/simple"}},
		{
			[]string{"install", "--index-url", "https://primary/", "--extra-index-url", "https://extra/", "requests"},
			[]string{"--index-url", "https://primary/", "--extra-index-url", "https://extra/"},
		},
	}
	for _, c := range cases {
		got := r.extractIndexURLFlags(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("input %v: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestUVResolver_ExtractIndexURLFlags(t *testing.T) {
	r := &uvResolver{}
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"pip", "install", "flask"}, nil},
		{[]string{"pip", "install", "--index-url", "https://internal/simple", "flask"}, []string{"--index-url", "https://internal/simple"}},
		{[]string{"pip", "install", "--index-url=https://internal/simple", "flask"}, []string{"--index-url=https://internal/simple"}},
		{[]string{"pip", "install", "--extra-index-url", "https://extra/simple", "flask"}, []string{"--extra-index-url", "https://extra/simple"}},
		{
			[]string{"pip", "install", "--index-url", "https://primary/", "--extra-index-url", "https://extra/", "flask"},
			[]string{"--index-url", "https://primary/", "--extra-index-url", "https://extra/"},
		},
	}
	for _, c := range cases {
		got := r.extractIndexURLFlags(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("input %v: got %v, want %v", c.in, got, c.want)
		}
	}
}
