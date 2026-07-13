package vault

import "errors"

var (
	// ErrVaultNotFound means no vault exists at the given path.
	ErrVaultNotFound = errors.New("vault not found")
	// ErrVaultExists means Create was pointed at an existing vault.
	ErrVaultExists = errors.New("vault already exists")
	// ErrFormatVersion means the vault was written by an
	// incompatible format version.
	ErrFormatVersion = errors.New("unsupported vault format version")
	// ErrSecretNotFound means no secret has the given name.
	ErrSecretNotFound = errors.New("secret not found")
	// ErrVersionNotFound means the secret has no such version.
	ErrVersionNotFound = errors.New("secret version not found")
	// ErrVersionDestroyed means the version's envelope was erased.
	ErrVersionDestroyed = errors.New("secret version destroyed")
	// ErrSecretDeleted means the secret was soft-deleted.
	ErrSecretDeleted = errors.New("secret deleted")
	// ErrInvalidName means the secret name breaks the name grammar.
	ErrInvalidName = errors.New("invalid secret name")
	// ErrCheckpointBlocked means a WAL checkpoint could not truncate
	// the log, usually because another process holds a read snapshot.
	ErrCheckpointBlocked = errors.New("wal checkpoint blocked")
)
