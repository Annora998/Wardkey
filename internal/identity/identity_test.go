package identity

import (
	"path/filepath"
	"testing"
)

func TestProcessIdentityValidate(t *testing.T) {
	valid := ProcessIdentity{
		PID:                 1234,
		ImagePath:           filepath.Join(t.TempDir(), "wardkey.exe"),
		ImageFileSHA256:     [32]byte{1},
		ProcessCreationTime: 1,
	}

	tests := []struct {
		name     string
		identity ProcessIdentity
		wantErr  bool
	}{
		{
			name:     "valid identity",
			identity: valid,
		},
		{
			name: "missing PID",
			identity: func() ProcessIdentity {
				value := valid
				value.PID = 0
				return value
			}(),
			wantErr: true,
		},
		{
			name: "missing image path",
			identity: func() ProcessIdentity {
				value := valid
				value.ImagePath = ""
				return value
			}(),
			wantErr: true,
		},
		{
			name: "relative image path",
			identity: func() ProcessIdentity {
				value := valid
				value.ImagePath = "wardkey.exe"
				return value
			}(),
			wantErr: true,
		},
		{
			name: "missing file hash",
			identity: func() ProcessIdentity {
				value := valid
				value.ImageFileSHA256 = [32]byte{}
				return value
			}(),
			wantErr: true,
		},
		{
			name: "missing process creation time",
			identity: func() ProcessIdentity {
				value := valid
				value.ProcessCreationTime = 0
				return value
			}(),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.identity.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
