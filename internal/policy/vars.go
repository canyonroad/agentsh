package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// varPattern matches ${VAR} or ${VAR:-fallback}
var varPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}]*))?\}`)

// ExpandVariables expands ${VAR} and ${VAR:-fallback} syntax in a string.
// Variables are looked up in vars map first, then environment.
// If a variable is undefined and has no fallback, returns an error.
func ExpandVariables(s string, vars map[string]string) (string, error) {
	var expandErr error

	result := varPattern.ReplaceAllStringFunc(s, func(match string) string {
		if expandErr != nil {
			return match
		}

		parts := varPattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		varName := parts[1]
		fallback := ""
		hasFallback := len(parts) > 2 && strings.Contains(match, ":-")
		if hasFallback {
			fallback = parts[2]
		}

		// Look up in provided vars first
		if val, ok := vars[varName]; ok {
			return val
		}

		// Fall back to environment
		if val := os.Getenv(varName); val != "" {
			return val
		}

		// Use fallback if provided
		if hasFallback {
			return fallback
		}

		// No value and no fallback - error
		expandErr = fmt.Errorf("undefined variable: %s", varName)
		return match
	})

	if expandErr != nil {
		return "", expandErr
	}
	return result, nil
}
