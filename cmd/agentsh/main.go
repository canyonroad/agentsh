package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agentsh/agentsh/internal/cli"
)

var version = "dev"
var commit = "unknown"

func versionString() string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "dev"
	}
	c := strings.TrimSpace(commit)
	if c == "" || strings.EqualFold(c, "unknown") {
		return v
	}
	// Avoid duplication when version already contains the commit (e.g. git-describe output).
	if strings.Contains(v, c) {
		return v
	}
	return v + "+" + c
}

func main() {
	ctx := context.Background()
	if err := cli.NewRoot(versionString()).ExecuteContext(ctx); err != nil {
		var ee *cli.ExitError
		if errors.As(err, &ee) {
			if msg := ee.Message(); msg != "" {
				fmt.Fprintln(os.Stderr, msg)
			}
			os.Exit(ee.Code())
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
