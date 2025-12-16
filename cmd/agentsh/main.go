package main

import (
	"context"
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/cli"
)

var version = "dev"

func main() {
	ctx := context.Background()
	if err := cli.NewRoot(version).ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

