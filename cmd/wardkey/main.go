package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wardkey/internal/cli"
)

func main() {
	executableName := strings.ToLower(filepath.Base(os.Args[0]))
	executableName = strings.TrimSuffix(executableName, ".exe")

	if executableName == "git-credential-wardkey" {
		if err := cli.ExecuteGitCredentialHelper(os.Args[1:], os.Stdin, os.Stdout); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "git-credential-wardkey:", err)
			os.Exit(1)
		}
		return
	}

	if err := cli.Execute(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "wardkey:", err)
		os.Exit(2)
	}
}
