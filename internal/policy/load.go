package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func LoadFromFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}
	return &p, nil
}

func ResolvePolicyPath(dir, name string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("policy dir is empty")
	}
	if !nameRe.MatchString(name) {
		return "", fmt.Errorf("invalid policy name")
	}
	try := []string{
		filepath.Join(dir, name+".yaml"),
		filepath.Join(dir, name+".yml"),
		filepath.Join(dir, name),
	}
	for _, p := range try {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("policy %q not found in %q", name, dir)
}
