//go:build !shimtest

package main

// shimConfRoot returns the root path for reading shim.conf.
// Production builds always read from the real host filesystem.
func shimConfRoot() string { return "/" }
