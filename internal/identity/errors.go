package identity

import "errors"

var (
	// ErrNotFound means no identity file exists at the given path.
	ErrNotFound = errors.New("identity not found")
	// ErrExists means Write was pointed at an existing identity.
	ErrExists = errors.New("identity already exists")
	// ErrUnsafePermissions means the identity file is readable by
	// group or world.
	ErrUnsafePermissions = errors.New("identity file permissions too open")
	// ErrUnsafeDirPermissions means the identity's containing
	// directory is accessible by group or world.
	ErrUnsafeDirPermissions = errors.New("identity directory permissions too open")
	// ErrDecryptFailed usually means the passphrase is wrong.
	ErrDecryptFailed = errors.New("identity decrypt failed")
	// ErrMalformed means the decrypted file held no age secret key.
	ErrMalformed = errors.New("identity file malformed")
)
