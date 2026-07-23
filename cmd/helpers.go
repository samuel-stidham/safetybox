package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/samuel-stidham/safetybox/internal/envelope"
	"github.com/samuel-stidham/safetybox/internal/identity"
	"github.com/samuel-stidham/safetybox/internal/secret"
	"github.com/samuel-stidham/safetybox/internal/vault"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

// warnLooseVaultPerms warns once per invocation when the vault file,
// its directory, or its WAL siblings grant group or world access. It
// runs from PersistentPreRun, so every verb that reads the vault gets
// the check without threading a warning through each open. A resolve
// error is left to the verb itself to surface, and a missing vault, the
// normal case before init, produces no warning.
func warnLooseVaultPerms(cobraCmd *cobra.Command, opts *options) {
	path, err := opts.resolveVaultPath()
	if err != nil {
		return
	}

	for _, loose := range vault.LoosePermissions(path) {
		printStderr(cobraCmd, fmt.Sprintf(
			"warning: %s %s has mode %04o, group or world can access it: run chmod %04o on it\n",
			loose.Label, loose.Path, loose.Mode, loose.Recommend,
		))
	}
}

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

	if err := completeInterruptedRekey(path); err != nil {
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

// completeInterruptedRekey heals the crash window in rekey's identity
// swap. If the identity file is missing but a staged `.new` sibling
// exists, a rekey died after moving the old key to `.bak` but before
// promoting the new one. The vault is already on the new key, so the
// staged file is the live key and is promoted into place. Any other
// state is left untouched.
func completeInterruptedRekey(identityPath string) error {
	if _, err := os.Stat(identityPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat identity %s: %w", identityPath, err)
	}

	staged := identityPath + ".new"

	if _, err := os.Stat(staged); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat staged identity %s: %w", staged, err)
	}

	if err := os.Rename(staged, identityPath); err != nil {
		// Two invocations can race this heal. If the identity now
		// exists, the other one promoted the staged file first and
		// this invocation can simply proceed.
		if _, statErr := os.Stat(identityPath); statErr == nil {
			return nil
		}

		return fmt.Errorf("complete interrupted rekey (your new identity is at %s): %w", staged, err)
	}

	return nil
}

// verifyRecipient refuses when the vault's stored recipient does not
// match the loaded identity. A vault-write attacker can swap the
// recipient so later writes seal to their key. The write path cannot
// catch that, because it never holds the identity, so the read path
// raises the alarm the moment the identity is present, even for old
// versions that still decrypt cleanly under the original key.
func verifyRecipient(expectedRecipient string, key *age.X25519Identity) error {
	if expectedRecipient == key.Recipient().String() {
		return nil
	}

	// The same mismatch has three innocent-to-hostile causes: a
	// tampered vault_meta, an interrupted rekey that left the old
	// identity in place, or simply the wrong identity. Name all three,
	// including the interrupted-rekey hint the decrypt path used to give.
	return fmt.Errorf(
		"%w: the vault may have been tampered with, or an interrupted rekey left the "+
			"wrong identity in place, check for a .new sibling of the identity file",
		ErrRecipientMismatch,
	)
}

// forEachDecrypted unlocks the identity once and opens every entry's
// envelope with it, calling fn with the entry and its plaintext. It
// is the single batch decrypt path, shared by exec and reveal, so a
// batch pays the passphrase KDF exactly one time and both verbs stay
// on one address-verification and expiry-warning behavior. It refuses
// before decrypting anything when the stored recipient does not match
// the identity.
func forEachDecrypted(cobraCmd *cobra.Command, opts *options, expectedRecipient string, entries []vault.Entry,
	visit func(entry vault.Entry, expired bool, value secret.Value) error,
) error {
	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return err
	}

	defer cleanup()

	if err := verifyRecipient(expectedRecipient, key); err != nil {
		return err
	}

	now := nowUTC()

	for _, entry := range entries {
		address := vault.CanonicalAddress(entry.Name, entry.Version)

		value, err := envelope.Open(key, address, entry.Envelope)
		if err != nil {
			return fmt.Errorf("open %s: %w", entry.Name, userHint(err))
		}

		expired := entry.Expired(now)
		if expired {
			warnExpired(cobraCmd, entry.Name, entry.ExpiresAt)
		}

		visitErr := visit(entry, expired, value)

		// The visitor has copied the plaintext into output or the child
		// environment by now, so wipe this decrypted copy rather than
		// leave it on the heap for the rest of the run.
		value.Destroy()

		if visitErr != nil {
			return visitErr
		}
	}

	return nil
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

	recipient, recipientErr := openedVault.Recipient()

	_ = openedVault.Close()

	if err != nil {
		return nil, userHint(err)
	}

	if recipientErr != nil {
		return nil, fmt.Errorf("read stored recipient: %w", recipientErr)
	}

	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	if err := verifyRecipient(recipient, key); err != nil {
		return nil, err
	}

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
