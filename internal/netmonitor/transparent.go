package netmonitor

import (
	"path/filepath"
	"strings"
)

// maxUnwrapDepth limits recursive unwrapping of chained transparent commands.
const maxUnwrapDepth = 5

// TransparentOverrides allows policy to add/remove transparent commands.
type TransparentOverrides struct {
	Add    []string `yaml:"add,omitempty"`
	Remove []string `yaml:"remove,omitempty"`
}

// commonTransparentCommands are transparent on all Unix-like platforms.
// These entries are harmless on Windows where these binaries don't exist —
// the map is just a lookup table and extra entries that never match have no effect.
var commonTransparentCommands = map[string]bool{
	"env":   true,
	"nice":  true,
	"nohup": true,
	"sudo":  true,
	"time":  true,
	"xargs": true,
}

// IsTransparentCommand checks if a basename is a transparent command,
// considering platform defaults and optional policy overrides.
func IsTransparentCommand(basename string, overrides *TransparentOverrides) bool {
	if overrides != nil {
		for _, r := range overrides.Remove {
			if strings.EqualFold(basename, r) {
				return false
			}
		}
		for _, a := range overrides.Add {
			if strings.EqualFold(basename, a) {
				return true
			}
		}
	}

	if commonTransparentCommands[basename] {
		return true
	}
	return isPlatformTransparentCommand(basename)
}

// isWindowsStyleFlag returns true for short Windows-style flags like /c, /k, /S.
// These are single-letter flags prefixed with / that appear in commands like
// cmd.exe /c or powershell.exe /C. We limit to exactly 1 alpha char after /
// to avoid matching Unix paths like /usr or /bin.
func isWindowsStyleFlag(arg string) bool {
	if len(arg) != 2 || arg[0] != '/' {
		return false
	}
	c := arg[1]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// UnwrapTransparentCommand peels transparent command wrappers to find the real payload.
// Returns the payload command (or the original if not transparent), the payload args,
// and the number of unwrap layers peeled.
//
// The heuristic skips flags (args starting with - or Windows-style /X flags),
// env-var assignments (args containing =), and treats -- as end-of-flags.
// The first remaining arg is the payload. This deliberately errs on the side of
// identifying more potential payloads rather than fewer — if a flag's value is
// mistakenly treated as a payload, it will simply not match any command rule
// and hit default-deny, which is the safe outcome.
func UnwrapTransparentCommand(filename string, argv []string, overrides *TransparentOverrides) (string, []string, int) {
	originalFilename := filename
	originalArgv := argv
	currentBase := filepath.Base(filename)
	currentArgs := argv

	for depth := 0; depth < maxUnwrapDepth; depth++ {
		if !IsTransparentCommand(currentBase, overrides) {
			if depth == 0 {
				return originalFilename, originalArgv, 0
			}
			return currentBase, currentArgs, depth
		}

		payloadIdx := -1
		args := currentArgs
		if len(args) > 0 {
			args = args[1:]
		}
		for i, arg := range args {
			if arg == "--" {
				// Everything after -- is the payload.
				if i+1 < len(args) {
					payloadIdx = i + 1
				}
				break
			}
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if isWindowsStyleFlag(arg) {
				continue
			}
			if strings.Contains(arg, "=") {
				continue
			}
			payloadIdx = i
			break
		}

		if payloadIdx < 0 {
			return originalFilename, originalArgv, 0
		}

		payloadCmd := args[payloadIdx]
		payloadArgs := args[payloadIdx:]
		currentBase = filepath.Base(payloadCmd)
		currentArgs = payloadArgs
	}

	if len(currentArgs) > 0 {
		return currentBase, currentArgs, maxUnwrapDepth
	}
	return originalFilename, originalArgv, 0
}
