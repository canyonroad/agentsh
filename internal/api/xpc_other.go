//go:build !darwin

package api

// DefaultXPCAllowList is empty on non-darwin platforms.
var DefaultXPCAllowList = []string{}

// DefaultXPCBlockPrefixes is empty on non-darwin platforms.
var DefaultXPCBlockPrefixes = []string{}

// DefaultXPCBlockList is empty on non-darwin platforms.
var DefaultXPCBlockList = []string{}
