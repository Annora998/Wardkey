package main

import (
	"fmt"
	"os"

	"wardkey/internal/cli"
)

func main() {
	if err := cli.ExecuteGitCredentialHelper(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "git-credential-wardkey:", err)
		os.Exit(1)
	}
}
