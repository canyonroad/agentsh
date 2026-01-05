//go:build darwin

package main

import "fmt"

// validateArgs parses and validates command line arguments.
func validateArgs(args []string) (cmd string, cmdArgs []string, err error) {
	if len(args) < 3 {
		return "", nil, fmt.Errorf("not enough arguments")
	}
	if args[1] != "--" {
		return "", nil, fmt.Errorf("missing -- separator")
	}
	return args[2], args[2:], nil
}
