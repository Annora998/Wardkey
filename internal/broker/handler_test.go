package broker

import "testing"

func TestIsWardkeyGitHelper(t *testing.T) {
	tests := []struct {
		name      string
		imagePath string
		want      bool
	}{
		{
			name:      "Windows path",
			imagePath: `E:\Wardkey\git-credential-wardkey.exe`,
			want:      true,
		},
		{
			name:      "forward slash path",
			imagePath: "E:/Wardkey/git-credential-wardkey.exe",
			want:      true,
		},
		{
			name:      "case insensitive",
			imagePath: `E:\Wardkey\GIT-CREDENTIAL-WARDKEY.EXE`,
			want:      true,
		},
		{
			name:      "different helper",
			imagePath: `E:\Wardkey\git-credential-other.exe`,
			want:      false,
		},
		{
			name:      "extra suffix",
			imagePath: `E:\Wardkey\git-credential-wardkey.exe.bak`,
			want:      false,
		},
		{
			name:      "empty path",
			imagePath: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWardkeyGitHelper(tt.imagePath); got != tt.want {
				t.Errorf("isWardkeyGitHelper(%q) = %t, want %t", tt.imagePath, got, tt.want)
			}
		})
	}
}

func TestIsGitExecutable(t *testing.T) {
	tests := []struct {
		name      string
		imagePath string
		want      bool
	}{
		{
			name:      "Windows path",
			imagePath: `C:\Program Files\Git\bin\git.exe`,
			want:      true,
		},
		{
			name:      "forward slash path",
			imagePath: "C:/Program Files/Git/bin/git.exe",
			want:      true,
		},
		{
			name:      "case insensitive",
			imagePath: `C:\Git\GIT.EXE`,
			want:      true,
		},
		{
			name:      "different executable",
			imagePath: `C:\Git\bash.exe`,
			want:      false,
		},
		{
			name:      "extra suffix",
			imagePath: `C:\Git\git.exe.bak`,
			want:      false,
		},
		{
			name:      "empty path",
			imagePath: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGitExecutable(tt.imagePath); got != tt.want {
				t.Errorf("isGitExecutable(%q) = %t, want %t", tt.imagePath, got, tt.want)
			}
		})
	}
}
