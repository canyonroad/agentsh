package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/cli"
)

var version = "dev"

func main() {
	ctx := context.Background()
	if err := cli.NewRoot(version).ExecuteContext(ctx); err != nil {
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
