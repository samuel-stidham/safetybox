package cmd

import (
	"errors"
	"fmt"

	"github.com/samuel-stidham/safetybox/internal/identity"
	"github.com/samuel-stidham/safetybox/internal/vault"
)

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

	switch {
	case errors.Is(err, vault.ErrVaultNotFound), errors.Is(err, identity.ErrNotFound):
		return fmt.Errorf("%w: run `safetybox init` first", err)
	case errors.Is(err, identity.ErrDecryptFailed):
		return fmt.Errorf("%w: check the passphrase", err)
	case errors.Is(err, identity.ErrUnsafePermissions):
		return fmt.Errorf("%w: run `chmod 600` on the identity file", err)
	case errors.Is(err, identity.ErrUnsafeDirPermissions):
		return fmt.Errorf("%w: run `chmod 700` on the identity directory", err)
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
