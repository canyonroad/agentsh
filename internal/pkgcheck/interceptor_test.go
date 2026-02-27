package pkgcheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyInstallCommand_NPM(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "npm install express",
			command: "npm",
			args:    []string{"install", "express"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "express"},
			},
		},
		{
			name:    "npm i express lodash",
			command: "npm",
			args:    []string{"i", "express", "lodash"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express", "lodash"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"i", "express", "lodash"},
			},
		},
		{
			name:    "npm add react with --save-dev",
			command: "npm",
			args:    []string{"add", "react", "--save-dev"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"react"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"add", "react", "--save-dev"},
			},
		},
		{
			name:    "npm install with --registry flag and value",
			command: "npm",
			args:    []string{"install", "--registry", "https://registry.example.com", "express"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "--registry", "https://registry.example.com", "express"},
			},
		},
		{
			name:    "npm install no args - new_packages_only returns nil",
			command: "npm",
			args:    []string{"install"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "npm install no args - all_installs returns bulk",
			command: "npm",
			args:    []string{"install"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: "npm",
				OrigArgs:    []string{"install"},
			},
		},
		{
			name:    "npm ci - new_packages_only returns nil",
			command: "npm",
			args:    []string{"ci"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "npm ci - all_installs returns bulk",
			command: "npm",
			args:    []string{"ci"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: "npm",
				OrigArgs:    []string{"ci"},
			},
		},
		{
			name:    "npm run build - not an install",
			command: "npm",
			args:    []string{"run", "build"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "full path /usr/bin/npm",
			command: "/usr/bin/npm",
			args:    []string{"install", "express"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express"},
				BulkInstall: false,
				OrigCommand: "/usr/bin/npm",
				OrigArgs:    []string{"install", "express"},
			},
		},
		{
			name:    "npm install with only flags - bulk in all_installs",
			command: "npm",
			args:    []string{"install", "--save-dev"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "--save-dev"},
			},
		},
		{
			name:    "npm install scoped package",
			command: "npm",
			args:    []string{"install", "@types/node"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"@types/node"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "@types/node"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
				assert.Equal(t, tt.want.OrigCommand, got.OrigCommand)
				assert.Equal(t, tt.want.OrigArgs, got.OrigArgs)
			}
		})
	}
}

func TestClassifyInstallCommand_PNPM(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "pnpm add react",
			command: "pnpm",
			args:    []string{"add", "react"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"react"},
				BulkInstall: false,
				OrigCommand: "pnpm",
				OrigArgs:    []string{"add", "react"},
			},
		},
		{
			name:    "pnpm add multiple packages",
			command: "pnpm",
			args:    []string{"add", "react", "react-dom", "--save-dev"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"react", "react-dom"},
				BulkInstall: false,
				OrigCommand: "pnpm",
				OrigArgs:    []string{"add", "react", "react-dom", "--save-dev"},
			},
		},
		{
			name:    "pnpm install - new_packages_only returns nil",
			command: "pnpm",
			args:    []string{"install"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "pnpm install - all_installs returns bulk",
			command: "pnpm",
			args:    []string{"install"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: "pnpm",
				OrigArgs:    []string{"install"},
			},
		},
		{
			name:    "pnpm i - all_installs returns bulk",
			command: "pnpm",
			args:    []string{"i"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "pnpm",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: "pnpm",
				OrigArgs:    []string{"i"},
			},
		},
		{
			name:    "pnpm run test - not an install",
			command: "pnpm",
			args:    []string{"run", "test"},
			scope:   "new_packages_only",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
			}
		})
	}
}

func TestClassifyInstallCommand_Yarn(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "yarn add react",
			command: "yarn",
			args:    []string{"add", "react"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"react"},
				BulkInstall: false,
				OrigCommand: "yarn",
				OrigArgs:    []string{"add", "react"},
			},
		},
		{
			name:    "yarn add with --dev flag",
			command: "yarn",
			args:    []string{"add", "typescript", "--dev"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"typescript"},
				BulkInstall: false,
				OrigCommand: "yarn",
				OrigArgs:    []string{"add", "typescript", "--dev"},
			},
		},
		{
			name:    "yarn install - new_packages_only returns nil",
			command: "yarn",
			args:    []string{"install"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "yarn install - all_installs returns bulk",
			command: "yarn",
			args:    []string{"install"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "yarn",
				Ecosystem:   EcosystemNPM,
				BulkInstall: true,
				OrigCommand: "yarn",
				OrigArgs:    []string{"install"},
			},
		},
		{
			name:    "yarn test - not an install",
			command: "yarn",
			args:    []string{"test"},
			scope:   "new_packages_only",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
			}
		})
	}
}

func TestClassifyInstallCommand_Pip(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "pip install requests",
			command: "pip",
			args:    []string{"install", "requests"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"requests"},
				BulkInstall: false,
				OrigCommand: "pip",
				OrigArgs:    []string{"install", "requests"},
			},
		},
		{
			name:    "pip3 install flask",
			command: "pip3",
			args:    []string{"install", "flask"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"flask"},
				BulkInstall: false,
				OrigCommand: "pip3",
				OrigArgs:    []string{"install", "flask"},
			},
		},
		{
			name:    "pip install multiple packages",
			command: "pip",
			args:    []string{"install", "requests", "flask", "django"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"requests", "flask", "django"},
				BulkInstall: false,
				OrigCommand: "pip",
				OrigArgs:    []string{"install", "requests", "flask", "django"},
			},
		},
		{
			name:    "pip install with --index-url flag and value",
			command: "pip",
			args:    []string{"install", "--index-url", "https://pypi.example.com/simple", "requests"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"requests"},
				BulkInstall: false,
				OrigCommand: "pip",
				OrigArgs:    []string{"install", "--index-url", "https://pypi.example.com/simple", "requests"},
			},
		},
		{
			name:    "pip install -r requirements.txt - new_packages_only returns nil",
			command: "pip",
			args:    []string{"install", "-r", "requirements.txt"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "pip install -r requirements.txt - all_installs returns bulk",
			command: "pip",
			args:    []string{"install", "-r", "requirements.txt"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: "pip",
				OrigArgs:    []string{"install", "-r", "requirements.txt"},
			},
		},
		{
			name:    "pip install --requirement requirements.txt - new_packages_only returns nil",
			command: "pip",
			args:    []string{"install", "--requirement", "requirements.txt"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "pip install --requirement - all_installs returns bulk",
			command: "pip",
			args:    []string{"install", "--requirement", "requirements.txt"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: "pip",
				OrigArgs:    []string{"install", "--requirement", "requirements.txt"},
			},
		},
		{
			name:    "pip freeze - not an install",
			command: "pip",
			args:    []string{"freeze"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "full path /usr/bin/pip3",
			command: "/usr/bin/pip3",
			args:    []string{"install", "requests"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"requests"},
				BulkInstall: false,
				OrigCommand: "/usr/bin/pip3",
				OrigArgs:    []string{"install", "requests"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
				assert.Equal(t, tt.want.OrigCommand, got.OrigCommand)
			}
		})
	}
}

func TestClassifyInstallCommand_UV(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "uv pip install requests",
			command: "uv",
			args:    []string{"pip", "install", "requests"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"requests"},
				BulkInstall: false,
				OrigCommand: "uv",
				OrigArgs:    []string{"pip", "install", "requests"},
			},
		},
		{
			name:    "uv add flask",
			command: "uv",
			args:    []string{"add", "flask"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"flask"},
				BulkInstall: false,
				OrigCommand: "uv",
				OrigArgs:    []string{"add", "flask"},
			},
		},
		{
			name:    "uv add multiple packages",
			command: "uv",
			args:    []string{"add", "flask", "requests"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"flask", "requests"},
				BulkInstall: false,
				OrigCommand: "uv",
				OrigArgs:    []string{"add", "flask", "requests"},
			},
		},
		{
			name:    "uv pip install -r requirements.txt - new_packages_only returns nil",
			command: "uv",
			args:    []string{"pip", "install", "-r", "requirements.txt"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "uv pip install -r - all_installs returns bulk",
			command: "uv",
			args:    []string{"pip", "install", "-r", "requirements.txt"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: "uv",
				OrigArgs:    []string{"pip", "install", "-r", "requirements.txt"},
			},
		},
		{
			name:    "uv pip install no args - new_packages_only returns nil",
			command: "uv",
			args:    []string{"pip", "install"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "uv pip install no args - all_installs returns bulk",
			command: "uv",
			args:    []string{"pip", "install"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "uv",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: "uv",
				OrigArgs:    []string{"pip", "install"},
			},
		},
		{
			name:    "uv run script - not an install",
			command: "uv",
			args:    []string{"run", "script.py"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "uv pip only - not an install",
			command: "uv",
			args:    []string{"pip"},
			scope:   "new_packages_only",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
			}
		})
	}
}

func TestClassifyInstallCommand_Poetry(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "poetry add django",
			command: "poetry",
			args:    []string{"add", "django"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"django"},
				BulkInstall: false,
				OrigCommand: "poetry",
				OrigArgs:    []string{"add", "django"},
			},
		},
		{
			name:    "poetry add multiple with --group flag",
			command: "poetry",
			args:    []string{"add", "pytest", "pytest-cov", "--group", "dev"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"pytest", "pytest-cov"},
				BulkInstall: false,
				OrigCommand: "poetry",
				OrigArgs:    []string{"add", "pytest", "pytest-cov", "--group", "dev"},
			},
		},
		{
			name:    "poetry install - new_packages_only returns nil",
			command: "poetry",
			args:    []string{"install"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "poetry install - all_installs returns bulk",
			command: "poetry",
			args:    []string{"install"},
			scope:   "all_installs",
			want: &InstallIntent{
				Tool:        "poetry",
				Ecosystem:   EcosystemPyPI,
				BulkInstall: true,
				OrigCommand: "poetry",
				OrigArgs:    []string{"install"},
			},
		},
		{
			name:    "poetry build - not an install",
			command: "poetry",
			args:    []string{"build"},
			scope:   "new_packages_only",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
			}
		})
	}
}

func TestClassifyInstallCommand_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		scope   string
		want    *InstallIntent
	}{
		{
			name:    "empty args",
			command: "npm",
			args:    nil,
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "empty scope defaults to new_packages_only",
			command: "npm",
			args:    []string{"install", "express"},
			scope:   "",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "express"},
			},
		},
		{
			name:    "unknown command",
			command: "cargo",
			args:    []string{"install", "ripgrep"},
			scope:   "new_packages_only",
			want:    nil,
		},
		{
			name:    "flag with equals form",
			command: "npm",
			args:    []string{"install", "--registry=https://example.com", "express"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "--registry=https://example.com", "express"},
			},
		},
		{
			name:    "Windows path with .exe",
			command: `C:\Program Files\nodejs\npm.exe`,
			args:    []string{"install", "express"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express"},
				BulkInstall: false,
				OrigCommand: `C:\Program Files\nodejs\npm.exe`,
				OrigArgs:    []string{"install", "express"},
			},
		},
		{
			name:    "package with version spec",
			command: "npm",
			args:    []string{"install", "express@4.18.0"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "npm",
				Ecosystem:   EcosystemNPM,
				Packages:    []string{"express@4.18.0"},
				BulkInstall: false,
				OrigCommand: "npm",
				OrigArgs:    []string{"install", "express@4.18.0"},
			},
		},
		{
			name:    "pip install with version constraint",
			command: "pip",
			args:    []string{"install", "requests>=2.28.0"},
			scope:   "new_packages_only",
			want: &InstallIntent{
				Tool:        "pip",
				Ecosystem:   EcosystemPyPI,
				Packages:    []string{"requests>=2.28.0"},
				BulkInstall: false,
				OrigCommand: "pip",
				OrigArgs:    []string{"install", "requests>=2.28.0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tt.want.Tool, got.Tool)
				assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
				assert.Equal(t, tt.want.Packages, got.Packages)
				assert.Equal(t, tt.want.BulkInstall, got.BulkInstall)
			}
		})
	}
}

func TestExtractPackages(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "simple packages",
			args: []string{"express", "lodash"},
			want: []string{"express", "lodash"},
		},
		{
			name: "packages with flags",
			args: []string{"--save-dev", "express", "-g", "lodash"},
			want: []string{"express", "lodash"},
		},
		{
			name: "flag with value",
			args: []string{"--registry", "https://example.com", "express"},
			want: []string{"express"},
		},
		{
			name: "flag with equals form",
			args: []string{"--registry=https://example.com", "express"},
			want: []string{"express"},
		},
		{
			name: "only flags",
			args: []string{"--save-dev", "-g"},
			want: nil,
		},
		{
			name: "empty args",
			args: nil,
			want: nil,
		},
		{
			name: "scoped npm package not treated as flag",
			args: []string{"@types/node", "@babel/core"},
			want: []string{"@types/node", "@babel/core"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackages(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHasFlag(t *testing.T) {
	assert.True(t, hasFlag([]string{"-r", "requirements.txt"}, "-r"))
	assert.True(t, hasFlag([]string{"--requirement", "requirements.txt"}, "--requirement"))
	assert.False(t, hasFlag([]string{"--save-dev"}, "-r"))
	assert.False(t, hasFlag(nil, "-r"))
	// --flag=value compact form
	assert.True(t, hasFlag([]string{"--requirement=requirements.txt"}, "--requirement"))
	assert.True(t, hasFlag([]string{"--index-url=https://example.com"}, "--index-url"))
}

func TestSkipGlobalFlags(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantSub   string
		wantRest  []string
	}{
		{
			name:     "no flags",
			args:     []string{"install", "express"},
			wantSub:  "install",
			wantRest: []string{"express"},
		},
		{
			name:     "flags before subcommand",
			args:     []string{"--python", "/usr/bin/python3", "install", "requests"},
			wantSub:  "install",
			wantRest: []string{"requests"},
		},
		{
			name:     "boolean flag before subcommand",
			args:     []string{"--verbose", "install", "requests"},
			wantSub:  "install",
			wantRest: []string{"requests"},
		},
		{
			name:     "flag=value before subcommand",
			args:     []string{"--prefix=/custom", "install", "requests"},
			wantSub:  "install",
			wantRest: []string{"requests"},
		},
		{
			name:     "only flags no subcommand",
			args:     []string{"--verbose", "--debug"},
			wantSub:  "",
			wantRest: nil,
		},
		{
			name:     "empty args",
			args:     nil,
			wantSub:  "",
			wantRest: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub, rest := skipGlobalFlags(tt.args)
			assert.Equal(t, tt.wantSub, sub)
			assert.Equal(t, tt.wantRest, rest)
		})
	}
}

func TestClassifyInstallCommand_WindowsExtensions(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		wantTool string
	}{
		{
			name:     "npm.cmd",
			command:  `C:\nodejs\npm.cmd`,
			args:     []string{"install", "express"},
			wantTool: "npm",
		},
		{
			name:     "pip.bat",
			command:  `C:\Python\pip.bat`,
			args:     []string{"install", "requests"},
			wantTool: "pip",
		},
		{
			name:     "yarn.CMD uppercase",
			command:  `C:\yarn\yarn.CMD`,
			args:     []string{"add", "react"},
			wantTool: "yarn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, "new_packages_only")
			require.NotNil(t, got, "expected non-nil intent for %s", tt.command)
			assert.Equal(t, tt.wantTool, got.Tool)
		})
	}
}

func TestClassifyInstallCommand_GlobalFlagsBeforeSubcommand(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		scope    string
		wantTool string
		wantPkgs []string
	}{
		{
			name:     "pip --python /path install requests",
			command:  "pip",
			args:     []string{"--python", "/usr/bin/python3", "install", "requests"},
			scope:    "new_packages_only",
			wantTool: "pip",
			wantPkgs: []string{"requests"},
		},
		{
			name:     "npm --prefix /path install express",
			command:  "npm",
			args:     []string{"--prefix", "/tmp/project", "install", "express"},
			scope:    "new_packages_only",
			wantTool: "npm",
			wantPkgs: []string{"express"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyInstallCommand(tt.command, tt.args, tt.scope)
			require.NotNil(t, got, "expected non-nil intent")
			assert.Equal(t, tt.wantTool, got.Tool)
			assert.Equal(t, tt.wantPkgs, got.Packages)
		})
	}
}

func TestExtractPackages_ExpandedValueFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "timeout flag value not treated as package",
			args: []string{"--timeout", "5", "requests"},
			want: []string{"requests"},
		},
		{
			name: "retries flag value not treated as package",
			args: []string{"--retries", "3", "flask"},
			want: []string{"flask"},
		},
		{
			name: "cache-dir flag value not treated as package",
			args: []string{"--cache-dir", "/tmp/cache", "django"},
			want: []string{"django"},
		},
		{
			name: "proxy flag value not treated as package",
			args: []string{"--proxy", "http://proxy:8080", "requests"},
			want: []string{"requests"},
		},
		{
			name: "target -t short flag",
			args: []string{"-t", "/tmp/target", "numpy"},
			want: []string{"numpy"},
		},
		{
			name: "trusted-host flag",
			args: []string{"--trusted-host", "pypi.example.com", "requests"},
			want: []string{"requests"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackages(tt.args)
			assert.Equal(t, tt.want, got)
		})
	}
}
