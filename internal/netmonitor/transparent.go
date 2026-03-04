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

// UnwrapTransparentCommand peels transparent command wrappers to find the real payload.
// Returns the payload command (or the original if not transparent), the payload args,
// and the number of unwrap layers peeled.
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
		skipNext := false
		for i, arg := range args {
			if skipNext {
				skipNext = false
				continue
			}
			if arg == "--" {
				// Everything after -- is the payload.
				if i+1 < len(args) {
					payloadIdx = i + 1
				}
				break
			}
			if strings.HasPrefix(arg, "-") {
				// Short flags like -n may consume the next arg as their value.
				// Long flags with = (--foo=bar) are self-contained.
				if !strings.Contains(arg, "=") && !strings.HasPrefix(arg, "--") {
					skipNext = true
				}
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
