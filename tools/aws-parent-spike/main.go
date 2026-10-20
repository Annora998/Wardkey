package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const wardkeyExecutable = `E:\Wardkey\wardkey.exe`

func main() {
	if len(os.Args) != 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: aws.exe <Wardkey profile>")
		os.Exit(2)
	}

	command := exec.Command(wardkeyExecutable, "aws-credential-process", os.Args[1])
	command.Stdin = os.Stdin
	command.Stderr = os.Stderr

	output, err := command.Output()
	defer clear(output)

	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "AWS parent probe could not run the Wardkey helper.")
		os.Exit(1)
	}

	var response map[string]json.RawMessage
	if err := json.Unmarshal(output, &response); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL: helper response was not valid JSON.")
		os.Exit(1)
	}

	var version int
	if err := json.Unmarshal(response["Version"], &version); err != nil ||
		version != 1 ||
		!hasNonEmptyJSONString(response["AccessKeyId"]) ||
		!hasNonEmptyJSONString(response["SecretAccessKey"]) {
		fmt.Fprintln(os.Stderr, "FAIL: helper response did not contain AWS credential_process fields.")
		os.Exit(1)
	}

	_, _ = bytes.NewBuffer(output), response // Keep parsing data local; never print credential values.
	fmt.Println("PASS: Wardkey returned AWS credential_process JSON. Credential values were suppressed.")
}

func hasNonEmptyJSONString(raw json.RawMessage) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && value != ""
}
