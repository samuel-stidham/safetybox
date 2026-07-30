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
	// ErrStoredTimeCorrupt means a timestamp column holds a value no
	// safetybox writer produces, such as an empty string or arbitrary
	// text. A vault-write edit is the likely cause. A read fails whole
	// rather than skipping the one secret, because real corruption must
	// not be quietly tolerated, and the error names the secret and the
	// column so an operator can see what was edited.
	ErrStoredTimeCorrupt = errors.New("stored timestamp is not valid, the vault may have been edited")
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
	// ErrEnvelopeCurrent tells the legacy repair pass that a row already
	// holds a current-format envelope and needs no work. A resealer
	// returns it in place of an envelope, and the pass skips that row
	// rather than treating it as a failure.
	ErrEnvelopeCurrent = errors.New("envelope is already in the current format")
	// ErrRecipientMismatch means the vault's stored recipient does not
	// match the identity presented to migrate, so migrate refuses before
	// re-sealing every envelope, the way the read verbs refuse.
	ErrRecipientMismatch = errors.New("vault recipient does not match your identity")
)
