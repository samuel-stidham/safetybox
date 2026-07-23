package vault

import "errors"

var (
	// ErrVaultNotFound means no vault exists at the given path.
	ErrVaultNotFound = errors.New("vault not found")
	// ErrVaultExists means Create was pointed at an existing vault.
	ErrVaultExists = errors.New("vault already exists")
	// ErrVaultCorrupt means the file at the vault path exists but has
	// no schema or metadata, usually a half-created vault left by an
	// init that crashed before its schema transaction committed.
	ErrVaultCorrupt = errors.New("vault is not initialized or is corrupt")
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
	// ErrCommitAmbiguous means a commit reported an error after its
	// record may already have become durable in the WAL, so whether
	// the transaction landed is unknown. A failed fsync is the
	// canonical case. Callers whose failure cleanup is destructive
	// must not treat this as proof the transaction rolled back.
	ErrCommitAmbiguous = errors.New("commit failed with unknown outcome")
	// ErrAlreadyCurrentFormat means a migration was asked to upgrade a
	// vault that is already at the current format, so there is nothing
	// to do. A re-run after a crash reaches this cleanly.
	ErrAlreadyCurrentFormat = errors.New("vault is already at the current format")
	// ErrRecipientMismatch means the vault's stored recipient does not
	// match the identity presented to migrate, so migrate refuses before
	// re-sealing every envelope, the way the read verbs refuse.
	ErrRecipientMismatch = errors.New("vault recipient does not match your identity")
)
