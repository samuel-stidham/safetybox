package cmd

import (
	"fmt"

	"github.com/samuel-stidham/safetybox/internal/envelope"
	"github.com/samuel-stidham/safetybox/internal/identity"
	"github.com/samuel-stidham/safetybox/internal/secret"
	"github.com/samuel-stidham/safetybox/internal/vault"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

// openVault resolves the vault path and opens it with a user-facing
// hint on failure.
func (o *options) openVault() (*vault.Vault, error) {
	path, err := o.resolveVaultPath()
	if err != nil {
		return nil, err
	}

	opened, err := vault.Open(path)
	if err != nil {
		return nil, userHint(err)
	}

	return opened, nil
}

// storedRecipient reads and parses the vault's recipient. Write verbs
// need nothing else, which is the point of the asymmetric model.
func storedRecipient(openedVault *vault.Vault) (*age.X25519Recipient, error) {
	stored, err := openedVault.Recipient()
	if err != nil {
		return nil, fmt.Errorf("read stored recipient: %w", err)
	}

	recipient, err := age.ParseX25519Recipient(stored)
	if err != nil {
		return nil, fmt.Errorf("stored recipient does not parse: %w", err)
	}

	return recipient, nil
}

// loadIdentity reads the passphrase and decrypts the identity file.
// The returned cleanup wipes the key material and must be deferred.
func loadIdentity(cobraCmd *cobra.Command, opts *options) (*age.X25519Identity, func(), error) {
	path, err := opts.resolveIdentityPath()
	if err != nil {
		return nil, nil, err
	}

	passphrase, err := readPassphrase(cobraCmd, opts.passphraseFile, "Passphrase: ")
	if err != nil {
		return nil, nil, err
	}

	defer zeroBytes(passphrase)

	key, cleanup, err := identity.Load(path, passphrase)
	if err != nil {
		return nil, nil, userHint(err)
	}

	return key, cleanup, nil
}

// resolved is a decrypted secret with its metadata.
type resolved struct {
	meta    vault.SecretMeta
	version vault.VersionMeta
	value   secret.Value
}

// resolveNewest fetches, decrypts, and address-verifies the newest
// enabled version of name. It warns on stderr when the secret is
// expired, and still resolves it.
func resolveNewest(cobraCmd *cobra.Command, opts *options, name string) (*resolved, error) {
	openedVault, err := opts.openVault()
	if err != nil {
		return nil, err
	}

	newest, err := openedVault.NewestEnabled(name)

	_ = openedVault.Close()

	if err != nil {
		return nil, userHint(err)
	}

	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	address := vault.CanonicalAddress(name, newest.Version.Number)

	value, err := envelope.Open(key, address, newest.Envelope)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, userHint(err))
	}

	if newest.Secret.Expired(nowUTC()) {
		warnExpired(cobraCmd, name, newest.Secret.ExpiresAt)
	}

	return &resolved{meta: newest.Secret, version: newest.Version, value: value}, nil
}
