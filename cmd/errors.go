package cmd

import (
	"errors"
	"fmt"

	"github.com/samuel-stidham/safetybox/internal/envelope"
	"github.com/samuel-stidham/safetybox/internal/identity"
	"github.com/samuel-stidham/safetybox/internal/vault"
)

// ErrRecipientMismatch means the vault's stored recipient does not
// match the loaded identity. That points at a tampered vault_meta
// recipient, the attack the address binding does not cover, or simply
// the wrong identity for this vault.
var ErrRecipientMismatch = errors.New("vault recipient does not match your identity")

// exitCodeError carries a child process exit code from exec back to
// Execute. It is a struct error because the handler must read the
// code, which a plain sentinel cannot carry.
type exitCodeError struct {
	code int
}

func (e exitCodeError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.code)
}

// userHint decorates well-known sentinels with what to do next. This
// is the cmd boundary where internal errors become user guidance.
func userHint(err error) error {
	if err == nil {
		return nil
	}

	if hinted := keyMaterialHint(err); hinted != nil {
		return hinted
	}

	switch {
	case errors.Is(err, vault.ErrVaultNotFound):
		return fmt.Errorf("%w: run `safetybox init` first", err)
	case errors.Is(err, vault.ErrVaultCorrupt):
		return fmt.Errorf(
			"%w: the file at the vault path looks half-created, likely from an "+
				"interrupted init: inspect it, move it aside, then run `safetybox init`",
			err,
		)
	case errors.Is(err, vault.ErrVaultExists):
		return fmt.Errorf(
			"%w: if a previous init was interrupted, this may be a half-created "+
				"husk: inspect it and move it aside before retrying",
			err,
		)
	case errors.Is(err, vault.ErrSecretDeleted):
		return fmt.Errorf("%w: `set` a new value to revive it or `purge` it for good", err)
	case errors.Is(err, vault.ErrVersionNotFound):
		return fmt.Errorf("%w: `show` the secret to see its versions", err)
	case errors.Is(err, vault.ErrFormatVersion):
		return fmt.Errorf("%w: upgrade safetybox to open this vault", err)
	default:
		return err
	}
}

// keyMaterialHint covers the identity and envelope sentinels, or
// returns nil when err is neither.
func keyMaterialHint(err error) error {
	switch {
	case errors.Is(err, identity.ErrNotFound):
		return fmt.Errorf("%w: run `safetybox init` first", err)
	case errors.Is(err, identity.ErrDecryptFailed):
		return fmt.Errorf("%w: check the passphrase", err)
	case errors.Is(err, identity.ErrUnsafePermissions):
		return fmt.Errorf("%w: run `chmod 600` on the identity file", err)
	case errors.Is(err, identity.ErrUnsafeDirPermissions):
		return fmt.Errorf("%w: run `chmod 700` on the identity directory", err)
	case errors.Is(err, identity.ErrExists):
		return fmt.Errorf("%w: a previous run may have left a stale file, move it aside", err)
	case errors.Is(err, envelope.ErrDecryptFailed):
		return fmt.Errorf(
			"%w: the identity may not match this vault, check for an interrupted rekey (a .new sibling of the identity file)",
			err,
		)
	default:
		return nil
	}
}
