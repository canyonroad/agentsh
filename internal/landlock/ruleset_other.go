//go:build !linux

package landlock

import "errors"

// RulesetBuilder constructs a Landlock ruleset from paths.
type RulesetBuilder struct {
	abi          int
	workspace    string
	executePaths []string
	readPaths    []string
	writePaths   []string
	denyPaths    []string
	allowNetwork bool
	allowBind    bool
}

// NewRulesetBuilder creates a new ruleset builder for the given ABI version.
func NewRulesetBuilder(abi int) *RulesetBuilder {
	return &RulesetBuilder{
		abi:          abi,
		executePaths: make([]string, 0),
		readPaths:    make([]string, 0),
		writePaths:   make([]string, 0),
		denyPaths:    make([]string, 0),
	}
}

// SetWorkspace sets the workspace path.
func (b *RulesetBuilder) SetWorkspace(path string) {
	b.workspace = path
}

// AddExecutePath adds a path where execution is allowed.
func (b *RulesetBuilder) AddExecutePath(path string) error {
	b.executePaths = append(b.executePaths, path)
	return nil
}

// AddReadPath adds a path where reading is allowed.
func (b *RulesetBuilder) AddReadPath(path string) error {
	b.readPaths = append(b.readPaths, path)
	return nil
}

// AddWritePath adds a path where writing is allowed.
func (b *RulesetBuilder) AddWritePath(path string) error {
	b.writePaths = append(b.writePaths, path)
	return nil
}

// AddDenyPath marks a path to be denied.
func (b *RulesetBuilder) AddDenyPath(path string) {
	b.denyPaths = append(b.denyPaths, path)
}

// SetNetworkAccess configures network restrictions.
func (b *RulesetBuilder) SetNetworkAccess(connect, bind bool) {
	b.allowNetwork = connect
	b.allowBind = bind
}

// isDenied checks if a path is in the deny list.
func (b *RulesetBuilder) isDenied(path string) bool {
	for _, deny := range b.denyPaths {
		if path == deny {
			return true
		}
	}
	return false
}

// Build returns an error on non-Linux platforms.
func (b *RulesetBuilder) Build() (int, error) {
	return -1, errors.New("Landlock not supported on this platform")
}

// Enforce returns an error on non-Linux platforms.
func Enforce(rulesetFd int) error {
	return errors.New("Landlock not supported on this platform")
}
