//go:build darwin && cgo

package sandboxext

/*
#include <sandbox.h>
#include <stdlib.h>

// sandbox_extension_issue_file is a private API for issuing sandbox extension tokens.
extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

// sandbox_extension_consume consumes a token, granting the calling process access.
extern int64_t sandbox_extension_consume(const char *token);

// sandbox_extension_release releases a previously consumed extension.
extern int sandbox_extension_release(int64_t handle);
*/
import "C"

import (
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// ExtClass represents a sandbox extension class that determines the access level.
type ExtClass string

const (
	// ReadOnly grants read-only access to the path.
	ReadOnly ExtClass = "com.apple.app-sandbox.read"
	// ReadWrite grants read-write access to the path.
	ReadWrite ExtClass = "com.apple.app-sandbox.read-write"
)

// Token represents a sandbox extension token for a specific path.
type Token struct {
	Path   string
	Class  ExtClass
	Value  string    // opaque token string from sandbox_extension_issue_file
	Issued time.Time
	handle int64 // internal handle from consume, -1 if not consumed
}

// Manager manages sandbox extension tokens. It lives server-side and issues
// tokens that grant path-specific access to sandboxed processes.
type Manager struct {
	mu     sync.Mutex
	tokens map[string]*Token
}

// NewManager creates a new Manager with an empty token map.
func NewManager() *Manager {
	return &Manager{
		tokens: make(map[string]*Token),
	}
}

// Issue calls sandbox_extension_issue_file to create a token granting access
// to path at the given extension class. The token is stored internally keyed
// by path.
func (m *Manager) Issue(path string, class ExtClass) (*Token, error) {
	cClass := C.CString(string(class))
	defer C.free(unsafe.Pointer(cClass))

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	cToken := C.sandbox_extension_issue_file(cClass, cPath, 0)
	if cToken == nil {
		return nil, fmt.Errorf("sandbox_extension_issue_file failed for path %q class %q", path, class)
	}
	defer C.free(unsafe.Pointer(cToken))

	tok := &Token{
		Path:   path,
		Class:  class,
		Value:  C.GoString(cToken),
		Issued: time.Now(),
		handle: -1,
	}

	m.mu.Lock()
	m.tokens[path] = tok
	m.mu.Unlock()

	return tok, nil
}

// ActiveTokens returns copies of all active tokens.
func (m *Manager) ActiveTokens() []Token {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]Token, 0, len(m.tokens))
	for _, tok := range m.tokens {
		result = append(result, *tok)
	}
	return result
}

// Revoke removes the token for the given path. If the token was consumed,
// sandbox_extension_release is called. Returns nil if the path has no active
// token (double-revoke is safe).
func (m *Manager) Revoke(path string) error {
	m.mu.Lock()
	tok, ok := m.tokens[path]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	delete(m.tokens, path)
	m.mu.Unlock()

	if tok.handle >= 0 {
		C.sandbox_extension_release(C.int64_t(tok.handle))
	}
	return nil
}

// RevokeAll revokes all active tokens.
func (m *Manager) RevokeAll() {
	m.mu.Lock()
	tokens := m.tokens
	m.tokens = make(map[string]*Token)
	m.mu.Unlock()

	for _, tok := range tokens {
		if tok.handle >= 0 {
			C.sandbox_extension_release(C.int64_t(tok.handle))
		}
	}
}

// TokenValues returns just the opaque token strings for all active tokens.
// This is useful for serialization into WrapperConfig JSON.
func (m *Manager) TokenValues() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]string, 0, len(m.tokens))
	for _, tok := range m.tokens {
		result = append(result, tok.Value)
	}
	return result
}

// ConsumeToken is a standalone function (not a Manager method) that calls
// sandbox_extension_consume. It is used client-side in macwrap to consume
// tokens received from the server. Returns a handle >= 0 on success.
func ConsumeToken(tokenStr string) (int64, error) {
	cToken := C.CString(tokenStr)
	defer C.free(unsafe.Pointer(cToken))

	handle := int64(C.sandbox_extension_consume(cToken))
	if handle < 0 {
		return handle, fmt.Errorf("sandbox_extension_consume failed (handle=%d)", handle)
	}
	return handle, nil
}
