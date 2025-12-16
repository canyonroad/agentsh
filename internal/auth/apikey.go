package auth

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type APIKeyAuth struct {
	headerName string
	keys       map[string]string // key -> role
}

type keyFileEntry struct {
	ID          string `yaml:"id"`
	Key         string `yaml:"key"`
	Description string `yaml:"description"`
	Role        string `yaml:"role"` // agent|approver|admin
}

func LoadAPIKeys(keysFile string, headerName string) (*APIKeyAuth, error) {
	if strings.TrimSpace(headerName) == "" {
		headerName = "X-API-Key"
	}
	if keysFile == "" {
		return nil, fmt.Errorf("api key auth enabled but keys_file is empty")
	}
	b, err := os.ReadFile(keysFile)
	if err != nil {
		return nil, fmt.Errorf("read api keys file: %w", err)
	}
	var entries []keyFileEntry
	if err := yaml.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("parse api keys file: %w", err)
	}
	keys := make(map[string]string, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.Key) == "" {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(e.Role))
		if role == "" {
			role = "admin"
		}
		keys[e.Key] = role
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("api keys file contains no keys")
	}
	return &APIKeyAuth{headerName: headerName, keys: keys}, nil
}

func (a *APIKeyAuth) HeaderName() string { return a.headerName }

func (a *APIKeyAuth) IsAllowed(key string) bool {
	_, ok := a.keys[key]
	return ok
}

func (a *APIKeyAuth) RoleForKey(key string) string {
	if a == nil {
		return ""
	}
	role, ok := a.keys[key]
	if !ok {
		return ""
	}
	return role
}
