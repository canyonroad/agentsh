//go:build shimtest

package main

import "os"

// shimConfRoot returns the root path for reading shim.conf.
// Test builds allow AGENTSH_SHIM_CONF_ROOT override for integration testing.
// This file is only compiled with -tags shimtest.
func shimConfRoot() string {
	if v := os.Getenv("AGENTSH_SHIM_CONF_ROOT"); v != "" {
		return v
	}
	return "/"
}
