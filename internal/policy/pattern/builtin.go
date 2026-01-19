package pattern

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// BuiltinClasses defines the default built-in process classes.
// These can be extended or overridden via configuration.
var BuiltinClasses = map[string][]string{
	// Shell processes
	"shell": {
		"bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh", "csh",
		"pwsh", "powershell", // PowerShell
		"nu", "nushell",      // Nushell
		"xonsh",              // Xonsh
		"elvish",             // Elvish
	},

	// Code editors and IDEs
	"editor": {
		// Electron-based editors
		"Cursor", "cursor",
		"Code", "code", "code-oss", // VS Code
		"codium",                   // VSCodium
		"Atom", "atom",
		"Zed", "zed",
		// Traditional editors
		"vim", "nvim", "neovim",
		"emacs", "emacsclient",
		"nano", "pico",
		"micro",
		"helix", "hx",
		"kakoune", "kak",
		// IDEs
		"idea", "idea64", "intellij*",          // IntelliJ
		"goland", "goland64",                   // GoLand
		"pycharm", "pycharm64",                 // PyCharm
		"webstorm", "webstorm64",               // WebStorm
		"clion", "clion64",                     // CLion
		"rustrover",                            // RustRover
		"rider", "rider64",                     // Rider
		"eclipse",                              // Eclipse
		"sublime_text", "subl",                 // Sublime Text
		"TextMate",                             // TextMate
		"notepad++",                            // Notepad++
		"gedit", "kate", "geany", "mousepad",   // GTK/KDE editors
	},

	// AI agents and assistants
	"agent": {
		"claude-agent", "claude",
		"aider", "aider-chat",
		"copilot", "github-copilot",
		"cody",
		"continue",
		"cursor-agent",
		"windsurf",
		"tabnine",
		"kite",
		"sourcegraph",
	},

	// Build tools and package managers
	"build": {
		// Node.js
		"npm", "npx", "yarn", "pnpm", "bun",
		// Python
		"pip", "pip3", "poetry", "pdm", "uv", "hatch", "pipx",
		// Rust
		"cargo", "rustc",
		// Go
		"go",
		// Java/JVM
		"mvn", "maven", "gradle", "gradlew", "sbt", "ant",
		// C/C++
		"make", "cmake", "ninja", "meson", "bazel",
		"gcc", "g++", "clang", "clang++",
		// Ruby
		"gem", "bundle", "bundler", "rake",
		// PHP
		"composer",
		// .NET
		"dotnet", "nuget", "msbuild",
		// General
		"just", "task", "earthly",
	},

	// Language servers (LSP)
	"language-server": {
		// Generic patterns
		"*-language-server",
		"*-lsp",
		// TypeScript/JavaScript
		"tsserver", "typescript-language-server",
		"vscode-eslint-language-server",
		"vscode-json-language-server",
		"vscode-css-language-server",
		"vscode-html-language-server",
		"biome",
		// Go
		"gopls",
		// Rust
		"rust-analyzer", "rls",
		// Python
		"pylsp", "pyright", "python-language-server", "jedi-language-server",
		"ruff-lsp", "basedpyright",
		// C/C++
		"clangd", "ccls",
		// Ruby
		"solargraph", "ruby-lsp",
		// PHP
		"phpactor", "intelephense",
		// Java
		"jdtls", "java-language-server",
		// Lua
		"lua-language-server", "luals",
		// YAML/JSON
		"yaml-language-server",
		// Bash
		"bash-language-server",
		// Docker
		"docker-langserver",
		// Terraform
		"terraform-ls",
		// Markdown
		"marksman",
	},

	// Language runtimes
	"runtime": {
		// Node.js
		"node", "nodejs", "deno", "bun",
		// Python
		"python", "python3", "python2", "pypy", "pypy3",
		// Ruby
		"ruby", "irb",
		// PHP
		"php",
		// Java/JVM
		"java", "kotlin", "scala", "groovy",
		// .NET
		"dotnet",
		// Lua
		"lua", "luajit",
		// Perl
		"perl",
		// R
		"R", "Rscript",
		// Julia
		"julia",
		// Elixir/Erlang
		"elixir", "iex", "erl", "erlang",
	},

	// Test runners
	"test": {
		// JavaScript/TypeScript
		"jest", "mocha", "vitest", "playwright", "cypress",
		// Python
		"pytest", "python -m pytest", "nose", "unittest",
		// Go
		"go test",
		// Rust
		"cargo test",
		// Ruby
		"rspec", "minitest",
		// Java
		"junit", "testng",
		// General
		"ctest",
	},

	// Formatters and linters
	"formatter": {
		// JavaScript/TypeScript
		"prettier", "eslint", "biome",
		// Python
		"black", "ruff", "isort", "autopep8", "yapf", "flake8", "pylint", "mypy",
		// Go
		"gofmt", "goimports", "golangci-lint",
		// Rust
		"rustfmt", "clippy",
		// Ruby
		"rubocop",
		// General
		"pre-commit",
	},

	// Version control
	"vcs": {
		"git", "gh", "hub",
		"hg", "mercurial",
		"svn", "subversion",
	},

	// Container and orchestration tools
	"container": {
		"docker", "podman", "containerd", "runc", "crun",
		"kubectl", "k9s", "helm",
		"docker-compose", "docker compose",
	},
}

// ClassRegistry manages built-in and custom process classes.
type ClassRegistry struct {
	mu       sync.RWMutex
	classes  map[string][]string
	compiled map[string]*PatternSet // Compiled pattern sets for each class
}

// NewClassRegistry creates a new class registry with built-in classes.
func NewClassRegistry() *ClassRegistry {
	r := &ClassRegistry{
		classes:  make(map[string][]string),
		compiled: make(map[string]*PatternSet),
	}

	// Copy built-in classes
	for name, patterns := range BuiltinClasses {
		r.classes[name] = append([]string{}, patterns...)
	}

	return r
}

// Get returns the patterns for a class name (without @ prefix).
func (r *ClassRegistry) Get(name string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	patterns, ok := r.classes[name]
	if !ok {
		return nil, fmt.Errorf("unknown class: @%s", name)
	}

	// Return a copy to prevent modification
	result := make([]string, len(patterns))
	copy(result, patterns)
	return result, nil
}

// GetResolver returns a resolver function for use with Pattern.MatchWithResolver.
func (r *ClassRegistry) GetResolver() func(string) ([]string, error) {
	return r.Get
}

// Has checks if a class exists.
func (r *ClassRegistry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.classes[name]
	return ok
}

// Set adds or replaces a class.
func (r *ClassRegistry) Set(name string, patterns []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.classes[name] = append([]string{}, patterns...)
	delete(r.compiled, name) // Invalidate compiled cache
}

// Extend adds patterns to an existing class (or creates it if it doesn't exist).
func (r *ClassRegistry) Extend(name string, patterns []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing := r.classes[name]
	r.classes[name] = append(existing, patterns...)
	delete(r.compiled, name) // Invalidate compiled cache
}

// Delete removes a class.
func (r *ClassRegistry) Delete(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.classes, name)
	delete(r.compiled, name)
}

// List returns all registered class names, sorted alphabetically.
func (r *ClassRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.classes))
	for name := range r.classes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Matches checks if a string matches any pattern in a class.
func (r *ClassRegistry) Matches(name, input string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we have a compiled pattern set
	ps, ok := r.compiled[name]
	if !ok {
		patterns, exists := r.classes[name]
		if !exists {
			return false, fmt.Errorf("unknown class: @%s", name)
		}

		// Compile the pattern set
		var err error
		ps, err = NewPatternSet(patterns)
		if err != nil {
			return false, fmt.Errorf("failed to compile class @%s: %w", name, err)
		}
		r.compiled[name] = ps
	}

	return ps.MatchAny(input), nil
}

// ExpandClass is a convenience function that returns patterns for a class
// using the default built-in classes.
func ExpandClass(name string) ([]string, bool) {
	// Remove @ prefix if present
	name = strings.TrimPrefix(name, "@")

	patterns, ok := BuiltinClasses[name]
	if !ok {
		return nil, false
	}

	// Return a copy
	result := make([]string, len(patterns))
	copy(result, patterns)
	return result, true
}

// IsBuiltinClass checks if a class name (with or without @ prefix) is a built-in class.
func IsBuiltinClass(name string) bool {
	name = strings.TrimPrefix(name, "@")
	_, ok := BuiltinClasses[name]
	return ok
}

// DefaultRegistry is the default class registry with built-in classes.
var DefaultRegistry = NewClassRegistry()
