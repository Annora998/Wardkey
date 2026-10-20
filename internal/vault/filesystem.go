package vault

import "errors"

var ErrACLsRequired = errors.New(
	"vault storage requires a filesystem that preserves and enforces ACLs",
)

// FILE_PERSISTENT_ACLS from the Windows GetVolumeInformation API.
const persistentACLsFlag uint32 = 0x00000008

func checkACLFlags(flags uint32) error {
	if flags&persistentACLsFlag == 0 {
		return ErrACLsRequired
	}
	return nil
}
