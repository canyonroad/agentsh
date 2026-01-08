package kms

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// FileProvider loads keys from local files or environment variables.
type FileProvider struct {
	keyFile   string
	keyEnv    string
	cachedKey []byte
}

// NewFileProvider creates a provider that loads keys from a file or environment variable.
// At least one of keyFile or keyEnv must be specified.
func NewFileProvider(keyFile, keyEnv string) (*FileProvider, error) {
	if keyFile == "" && keyEnv == "" {
		return nil, fmt.Errorf("no key source specified: provide key_file or key_env")
	}
	return &FileProvider{
		keyFile: keyFile,
		keyEnv:  keyEnv,
	}, nil
}

// Name returns the provider identifier.
func (p *FileProvider) Name() string {
	if p.keyFile != "" {
		return "file:" + p.keyFile
	}
	return "env:" + p.keyEnv
}

// GetKey retrieves the key from file or environment variable.
// The key is cached after first successful retrieval.
func (p *FileProvider) GetKey(ctx context.Context) ([]byte, error) {
	if p.cachedKey != nil {
		return p.cachedKey, nil
	}

	var key []byte
	var err error

	if p.keyFile != "" {
		key, err = p.loadFromFile()
	} else {
		key, err = p.loadFromEnv()
	}

	if err != nil {
		return nil, err
	}

	p.cachedKey = key
	return key, nil
}

// loadFromFile reads the key from a file.
func (p *FileProvider) loadFromFile() ([]byte, error) {
	data, err := os.ReadFile(p.keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: key file %q does not exist", ErrKeyNotFound, p.keyFile)
		}
		return nil, fmt.Errorf("read key file %q: %w", p.keyFile, err)
	}

	key := strings.TrimSpace(string(data))
	if key == "" {
		return nil, fmt.Errorf("%w: key file %q is empty", ErrKeyNotFound, p.keyFile)
	}

	return []byte(key), nil
}

// loadFromEnv reads the key from an environment variable.
func (p *FileProvider) loadFromEnv() ([]byte, error) {
	key := os.Getenv(p.keyEnv)
	if key == "" {
		return nil, fmt.Errorf("%w: environment variable %q is empty or not set", ErrKeyNotFound, p.keyEnv)
	}
	return []byte(key), nil
}

// Close is a no-op for the file provider.
func (p *FileProvider) Close() error {
	return nil
}
