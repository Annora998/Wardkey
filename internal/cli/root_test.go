package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestExecute(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "help",
			args: []string{"help"},
			want: "wardkey <command>",
		},
		{
			name: "version",
			args: []string{"version"},
			want: "wardkey 0.1.0-dev",
		},
		{
			name:    "missing command",
			wantErr: true,
		},
		{
			name:    "unknown command",
			args:    []string{"unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Execute(tt.args, &out)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Errorf("output %q does not contain %q", out.String(), tt.want)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestExecuteReturnsOutputError(t *testing.T) {
	err := Execute([]string{"version"}, failingWriter{})
	if err == nil {
		t.Fatal("Execute() error = nil, want a write error")
	}
}