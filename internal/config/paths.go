package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrInvalidHome = errors.New("invalid Wardkey home configuration")

type Home struct {
	Path        string
	Development bool
	Warning     string
}

// ResolveHome selects the private default location or an explicitly marked
// development location. It does not create the directory.
func ResolveHome(getenv func(string) string) (Home, error) {
	if getenv == nil {
		return Home{}, ErrInvalidHome
	}

	devHome := strings.TrimSpace(getenv("WARDKEY_HOME"))
	devMode := getenv("WARDKEY_DEV") == "1"

	if devHome != "" {
		if !devMode || !filepath.IsAbs(devHome) {
			return Home{}, ErrInvalidHome
		}

		path := filepath.Clean(devHome)
		if filepath.Dir(path) == path {
			return Home{}, ErrInvalidHome
		}

		return Home{
			Path:        path,
			Development: true,
			Warning:     "DEVELOPMENT MODE: use dummy credentials only; this location may not enforce Windows file permissions.",
		}, nil
	}

	if devMode {
		return Home{}, ErrInvalidHome
	}

	localAppData := strings.TrimSpace(getenv("LOCALAPPDATA"))
	if localAppData == "" || !filepath.IsAbs(localAppData) {
		return Home{}, ErrInvalidHome
	}

	return Home{
		Path: filepath.Join(filepath.Clean(localAppData), "Wardkey"),
	}, nil
}

// DefaultHome resolves Wardkey's location from the current process environment.
func DefaultHome() (Home, error) {
	return ResolveHome(os.Getenv)
}
