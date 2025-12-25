package events

import (
	"regexp"
	"strings"
)

// SanitizePatterns contains patterns for sensitive content.
type SanitizePatterns struct {
	PathPatterns    []string `yaml:"path_patterns"`
	CmdlinePatterns []string `yaml:"cmdline_patterns"`
	EnvVarPatterns  []string `yaml:"env_var_patterns"`
}

// DefaultSensitivePatterns contains default patterns for sensitive content.
var DefaultSensitivePatterns = SanitizePatterns{
	PathPatterns: []string{
		`(?i)\.ssh`,
		`(?i)\.aws`,
		`(?i)\.kube`,
		`(?i)\.gnupg`,
		`(?i)/secrets?/`,
		`(?i)/credentials?/`,
		`(?i)/private/`,
		`(?i)\.env$`,
		`(?i)\.pem$`,
		`(?i)\.key$`,
		`(?i)\.p12$`,
		`(?i)password`,
		`(?i)token`,
		`(?i)api.?key`,
	},
	CmdlinePatterns: []string{
		`(?i)(--password[=\s]+)\S+`,
		`(?i)(--token[=\s]+)\S+`,
		`(?i)(--api-key[=\s]+)\S+`,
		`(?i)(-p\s+)\S+`,
		`(?i)(PASS(WORD)?=)\S+`,
		`(?i)(TOKEN=)\S+`,
		`(?i)(API_KEY=)\S+`,
		`(?i)(SECRET=)\S+`,
	},
	EnvVarPatterns: []string{
		`(?i).*PASSWORD.*`,
		`(?i).*SECRET.*`,
		`(?i).*TOKEN.*`,
		`(?i).*API.?KEY.*`,
		`(?i).*PRIVATE.?KEY.*`,
		`(?i).*CREDENTIAL.*`,
		`(?i)AWS_.*`,
		`(?i)GITHUB_TOKEN`,
		`(?i)NPM_TOKEN`,
	},
}

// Sanitizer handles redaction of sensitive information in events.
type Sanitizer struct {
	pathPatterns    []*regexp.Regexp
	contentPatterns []*regexp.Regexp
	envVarPatterns  []*regexp.Regexp
}

// NewSanitizer creates a new sanitizer with the given patterns.
func NewSanitizer(patterns SanitizePatterns) *Sanitizer {
	s := &Sanitizer{}

	for _, p := range patterns.PathPatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.pathPatterns = append(s.pathPatterns, re)
		}
	}

	for _, p := range patterns.CmdlinePatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.contentPatterns = append(s.contentPatterns, re)
		}
	}

	for _, p := range patterns.EnvVarPatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.envVarPatterns = append(s.envVarPatterns, re)
		}
	}

	return s
}

// NewDefaultSanitizer creates a sanitizer with default patterns.
func NewDefaultSanitizer() *Sanitizer {
	return NewSanitizer(DefaultSensitivePatterns)
}

// SanitizePath checks if a path matches sensitive patterns.
// Returns sanitized path and list of fields that were sanitized.
func (s *Sanitizer) SanitizePath(path string) (string, []string) {
	for _, re := range s.pathPatterns {
		if re.MatchString(path) {
			parts := strings.Split(path, "/")
			for i, part := range parts {
				if re.MatchString(part) {
					parts[i] = "[REDACTED]"
				}
			}
			return strings.Join(parts, "/"), []string{"path"}
		}
	}
	return path, nil
}

// SanitizeCmdline redacts sensitive values in command line arguments.
func (s *Sanitizer) SanitizeCmdline(cmdline []string) []string {
	result := make([]string, len(cmdline))
	for i, arg := range cmdline {
		result[i] = arg
		for _, re := range s.contentPatterns {
			result[i] = re.ReplaceAllString(result[i], "${1}[REDACTED]")
		}
	}
	return result
}

// ShouldSanitizeEnvVar checks if an environment variable should be redacted.
func (s *Sanitizer) ShouldSanitizeEnvVar(name string) bool {
	for _, re := range s.envVarPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// IsSensitivePath checks if a path matches any sensitive patterns.
func (s *Sanitizer) IsSensitivePath(path string) bool {
	for _, re := range s.pathPatterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
