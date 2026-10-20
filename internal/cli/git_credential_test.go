package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseGitCredentialInput(t *testing.T) {
	input := "protocol=https\nhost=GitHub.COM\npath=owner/repo\nusername=alice\n\n"

	got, err := parseGitCredentialInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseGitCredentialInput() error = %v", err)
	}

	if got.Protocol != "https" {
		t.Errorf("Protocol = %q, want https", got.Protocol)
	}
	if got.Host != "github.com" {
		t.Errorf("Host = %q, want github.com", got.Host)
	}
	if got.Path != "owner/repo" {
		t.Errorf("Path = %q, want owner/repo", got.Path)
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.Username)
	}
}

func TestParseGitCredentialInputIgnoresPassword(t *testing.T) {
	input := "protocol=https\nhost=example.com\npath=owner/repo\nusername=alice\npassword=should-not-be-used\n\n"

	got, err := parseGitCredentialInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseGitCredentialInput() error = %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.Username)
	}
}

func TestParseGitCredentialInputRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "non HTTPS protocol",
			input: "protocol=http\nhost=example.com\npath=owner/repo\nusername=alice\n\n",
		},
		{
			name:  "duplicate host",
			input: "protocol=https\nhost=example.com\nhost=other.com\npath=owner/repo\nusername=alice\n\n",
		},
		{
			name:  "invalid host",
			input: "protocol=https\nhost=example.com/other\npath=owner/repo\nusername=alice\n\n",
		},
		{
			name:  "path traversal",
			input: "protocol=https\nhost=example.com\npath=owner/../other\nusername=alice\n\n",
		},
		{
			name:  "missing username",
			input: "protocol=https\nhost=example.com\npath=owner/repo\n\n",
		},
		{
			name:  "username with slash",
			input: "protocol=https\nhost=example.com\npath=owner/repo\nusername=alice/admin\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseGitCredentialInput(strings.NewReader(tt.input)); err == nil {
				t.Fatal("parseGitCredentialInput() error = nil, want an error")
			}
		})
	}
}

func TestParseGitCredentialInputRejectsOversizedRequest(t *testing.T) {
	input := "protocol=https\nhost=example.com\npath=owner/repo\nusername=" +
		strings.Repeat("a", maxGitCredentialInput) + "\n\n"

	if _, err := parseGitCredentialInput(strings.NewReader(input)); err == nil {
		t.Fatal("parseGitCredentialInput() error = nil, want oversized-request error")
	}
}

func TestValidGitField(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  bool
	}{
		{name: "ordinary token", value: []byte("token-value_123"), want: true},
		{name: "empty", value: nil, want: false},
		{name: "newline", value: []byte("token\ninjected"), want: false},
		{name: "invalid UTF-8", value: []byte{0xff}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validGitField(tt.value); got != tt.want {
				t.Errorf("validGitField() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestWriteGitCredential(t *testing.T) {
	var output bytes.Buffer
	password := []byte("dummy-token")

	if err := writeGitCredential(&output, "alice", password); err != nil {
		t.Fatalf("writeGitCredential() error = %v", err)
	}

	want := "username=alice\npassword=dummy-token\n\n"
	if got := output.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}
