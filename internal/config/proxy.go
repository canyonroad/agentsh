package config

// ProxyConfig configures the embedded LLM proxy.
type ProxyConfig struct {
	Mode      string               `yaml:"mode"`
	Port      int                  `yaml:"port"`
	Upstreams ProxyUpstreamsConfig `yaml:"upstreams"`
}

type ProxyUpstreamsConfig struct {
	Anthropic string `yaml:"anthropic"`
	OpenAI    string `yaml:"openai"`
	ChatGPT   string `yaml:"chatgpt"`
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

func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		Mode: "embedded",
		Port: 0,
		Upstreams: ProxyUpstreamsConfig{
			Anthropic: "https://api.anthropic.com",
			OpenAI:    "https://api.openai.com",
			ChatGPT:   "https://chatgpt.com/backend-api",
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
