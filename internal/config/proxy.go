package config

// ProxyConfig configures the embedded LLM proxy.
type ProxyConfig struct {
	Mode       string               `yaml:"mode"`
	Port       int                  `yaml:"port"`
	Providers  ProxyProvidersConfig `yaml:"providers"`
	RateLimits LLMRateLimitsConfig  `yaml:"rate_limits"`
}

type ProxyProvidersConfig struct {
	Anthropic string `yaml:"anthropic"`
	OpenAI    string `yaml:"openai"`
}

// IsMCPOnly returns true if the proxy runs in MCP-interception-only mode.
func (c ProxyConfig) IsMCPOnly() bool {
	return c.Mode == "mcp-only"
}

// IsCustomOpenAI returns true if a non-default OpenAI URL is configured.
func (c ProxyProvidersConfig) IsCustomOpenAI() bool {
	return c.OpenAI != "" && c.OpenAI != "https://api.openai.com"
}

type DLPConfig struct {
	Mode           string                `yaml:"mode"`
	Patterns       DLPPatternsConfig     `yaml:"patterns"`
	CustomPatterns []CustomPatternConfig `yaml:"custom_patterns"`
}

type DLPPatternsConfig struct {
	Email      bool `yaml:"email"`
	Phone      bool `yaml:"phone"`
	CreditCard bool `yaml:"credit_card"`
	SSN        bool `yaml:"ssn"`
	APIKeys    bool `yaml:"api_keys"`
}

type CustomPatternConfig struct {
	Name    string `yaml:"name"`
	Display string `yaml:"display"`
	Regex   string `yaml:"regex"`
}

type LLMStorageConfig struct {
	StoreBodies bool                      `yaml:"store_bodies"`
	Retention   LLMStorageRetentionConfig `yaml:"retention"`
}

type LLMStorageRetentionConfig struct {
	MaxAgeDays int    `yaml:"max_age_days"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	Eviction   string `yaml:"eviction"`
}

// LLMRateLimitsConfig configures rate limiting for LLM API calls.
type LLMRateLimitsConfig struct {
	Enabled           bool `yaml:"enabled"`
	RequestsPerMinute int  `yaml:"requests_per_minute"`
	RequestBurst      int  `yaml:"request_burst"`
	TokensPerMinute   int  `yaml:"tokens_per_minute"`
	TokenBurst        int  `yaml:"token_burst"`
}

func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Providers: ProxyProvidersConfig{
			Anthropic: "https://api.anthropic.com",
			OpenAI:    "https://api.openai.com",
		},
	}
}

func DefaultDLPConfig() DLPConfig {
	return DLPConfig{
		Mode: "redact",
		Patterns: DLPPatternsConfig{
			Email:      true,
			Phone:      true,
			CreditCard: true,
			SSN:        true,
			APIKeys:    true,
		},
	}
}

func DefaultLLMStorageConfig() LLMStorageConfig {
	return LLMStorageConfig{
		StoreBodies: false,
		Retention: LLMStorageRetentionConfig{
			MaxAgeDays: 30,
			MaxSizeMB:  500,
			Eviction:   "oldest_first",
		},
	}
}
