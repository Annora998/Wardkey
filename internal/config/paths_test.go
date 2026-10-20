package config

import (
	"path/filepath"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestResolveHomeUsesLocalAppDataByDefault(t *testing.T) {
	home, err := ResolveHome(env(map[string]string{
		"LOCALAPPDATA": `C:\Users\tester\AppData\Local`,
	}))
	if err != nil {
		t.Fatalf("ResolveHome() error = %v", err)
	}

	want := filepath.Join(`C:\Users\tester\AppData\Local`, "Wardkey")
	if home.Path != want {
		t.Errorf("ResolveHome().Path = %q, want %q", home.Path, want)
	}
	if home.Development {
		t.Error("ResolveHome().Development = true, want false")
	}
}

func TestResolveHomeAllowsExplicitDevelopmentPath(t *testing.T) {
	home, err := ResolveHome(env(map[string]string{
		"WARDKEY_HOME": `E:\Wardkey\dev-home`,
		"WARDKEY_DEV":  "1",
	}))
	if err != nil {
		t.Fatalf("ResolveHome() error = %v", err)
	}
	if !home.Development {
		t.Error("ResolveHome().Development = false, want true")
	}
	if home.Warning == "" {
		t.Error("ResolveHome().Warning is empty, want a development warning")
	}
	if home.Path != filepath.Clean(`E:\Wardkey\dev-home`) {
		t.Errorf("ResolveHome().Path = %q, want cleaned development path", home.Path)
	}
}

func TestResolveHomeRejectsUnsafeDevelopmentConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
	}{
		{
			name: "override without development flag",
			values: map[string]string{
				"WARDKEY_HOME": `E:\Wardkey\dev-home`,
			},
		},
		{
			name: "development flag without override",
			values: map[string]string{
				"WARDKEY_DEV": "1",
			},
		},
		{
			name: "relative development path",
			values: map[string]string{
				"WARDKEY_HOME": `dev-home`,
				"WARDKEY_DEV":  "1",
			},
		},
		{
			name:   "missing local app data",
			values: map[string]string{},
		},
		{
			name: "relative local app data",
			values: map[string]string{
				"LOCALAPPDATA": `AppData\Local`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ResolveHome(env(tt.values)); err == nil {
				t.Fatal("ResolveHome() error = nil, want invalid configuration error")
			}
		})
	}
}
