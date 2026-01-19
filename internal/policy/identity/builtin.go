package identity

// BuiltinIdentities defines process identities for common AI tools and editors.
// These are used to detect taint sources for parent-conditional policies.
var BuiltinIdentities = map[string]*ProcessIdentity{
	"cursor": {
		Name:        "cursor",
		Description: "Cursor AI-powered code editor",
		Linux: &PlatformMatch{
			Comm:    []string{"cursor", "Cursor"},
			ExePath: []string{"*/cursor", "*/Cursor"},
		},
		Darwin: &PlatformMatch{
			Comm:     []string{"Cursor", "Cursor Helper*"},
			ExePath:  []string{"*/Cursor.app/*"},
			BundleID: []string{"com.cursor.Cursor"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"Cursor.exe", "cursor.exe"},
			ExePath: []string{"*\\Cursor\\*"},
		},
	},

	"vscode": {
		Name:        "vscode",
		Description: "Visual Studio Code",
		Linux: &PlatformMatch{
			Comm:    []string{"code", "code-oss"},
			ExePath: []string{"*/code", "*/code-oss", "*/vscode/*"},
		},
		Darwin: &PlatformMatch{
			Comm:     []string{"Code", "Code Helper*"},
			ExePath:  []string{"*/Visual Studio Code.app/*", "*/VSCode.app/*"},
			BundleID: []string{"com.microsoft.VSCode"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"Code.exe", "code.exe"},
			ExePath: []string{"*\\Microsoft VS Code\\*"},
		},
	},

	"claude-desktop": {
		Name:        "claude-desktop",
		Description: "Claude Desktop application",
		Linux: &PlatformMatch{
			Comm:    []string{"claude", "claude-desktop"},
			ExePath: []string{"*/claude*"},
		},
		Darwin: &PlatformMatch{
			Comm:     []string{"Claude"},
			ExePath:  []string{"*/Claude.app/*"},
			BundleID: []string{"com.anthropic.claude-desktop", "com.anthropic.claudedesktop"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"Claude.exe", "claude.exe"},
		},
	},

	"windsurf": {
		Name:        "windsurf",
		Description: "Windsurf AI editor",
		Linux: &PlatformMatch{
			Comm:    []string{"windsurf", "Windsurf"},
			ExePath: []string{"*/windsurf*"},
		},
		Darwin: &PlatformMatch{
			Comm:    []string{"Windsurf", "Windsurf Helper*"},
			ExePath: []string{"*/Windsurf.app/*"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"Windsurf.exe", "windsurf.exe"},
		},
	},

	"zed": {
		Name:        "zed",
		Description: "Zed code editor",
		Linux: &PlatformMatch{
			Comm:    []string{"zed", "Zed"},
			ExePath: []string{"*/zed", "*/Zed"},
		},
		Darwin: &PlatformMatch{
			Comm:     []string{"Zed"},
			ExePath:  []string{"*/Zed.app/*"},
			BundleID: []string{"dev.zed.Zed"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"Zed.exe", "zed.exe"},
		},
	},

	"aider": {
		Name:        "aider",
		Description: "Aider AI pair programming tool",
		AllPlatforms: &PlatformMatch{
			Comm:    []string{"aider", "aider-chat"},
			Cmdline: []string{"*aider*"},
		},
	},

	"continue": {
		Name:        "continue",
		Description: "Continue AI coding assistant",
		AllPlatforms: &PlatformMatch{
			Comm:    []string{"continue"},
			Cmdline: []string{"*continue*"},
		},
	},

	"copilot": {
		Name:        "copilot",
		Description: "GitHub Copilot",
		AllPlatforms: &PlatformMatch{
			Comm:    []string{"copilot*", "github-copilot*"},
			Cmdline: []string{"*copilot*"},
		},
	},

	"cody": {
		Name:        "cody",
		Description: "Sourcegraph Cody AI assistant",
		AllPlatforms: &PlatformMatch{
			Comm:    []string{"cody", "cody-agent"},
			Cmdline: []string{"*cody*"},
		},
	},

	"jetbrains-ai": {
		Name:        "jetbrains-ai",
		Description: "JetBrains AI Assistant",
		Linux: &PlatformMatch{
			Comm:    []string{"idea*", "goland*", "pycharm*", "webstorm*", "clion*", "rustrover*"},
			ExePath: []string{"*/idea/*", "*/goland/*", "*/pycharm/*"},
		},
		Darwin: &PlatformMatch{
			Comm:     []string{"idea", "goland", "pycharm", "webstorm", "clion"},
			BundleID: []string{"com.jetbrains.*"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"idea*.exe", "goland*.exe", "pycharm*.exe", "webstorm*.exe"},
		},
	},

	"warp": {
		Name:        "warp",
		Description: "Warp AI-powered terminal",
		Linux: &PlatformMatch{
			Comm:    []string{"warp", "warp-terminal"},
			ExePath: []string{"*/warp*"},
		},
		Darwin: &PlatformMatch{
			Comm:     []string{"Warp"},
			ExePath:  []string{"*/Warp.app/*"},
			BundleID: []string{"dev.warp.Warp-Stable"},
		},
		Windows: &PlatformMatch{
			ExeName: []string{"Warp.exe", "warp.exe"},
		},
	},
}

// LoadBuiltinIdentities adds all built-in identities to a ProcessMatcher.
func LoadBuiltinIdentities(m *ProcessMatcher) error {
	for _, identity := range BuiltinIdentities {
		if err := m.AddIdentity(identity); err != nil {
			return err
		}
	}
	return nil
}

// NewMatcherWithBuiltins creates a ProcessMatcher pre-loaded with built-in identities.
func NewMatcherWithBuiltins() (*ProcessMatcher, error) {
	m := NewProcessMatcher()
	if err := LoadBuiltinIdentities(m); err != nil {
		return nil, err
	}
	return m, nil
}
