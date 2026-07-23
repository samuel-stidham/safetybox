package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/samuel-stidham/safetybox/v3/internal/envelope"
	"github.com/samuel-stidham/safetybox/v3/internal/identity"
	"github.com/samuel-stidham/safetybox/v3/internal/secret"
	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// lockFileMode matches the identity file's private mode.
const lockFileMode = 0o600

// acquireIdentityLock serializes the verbs that rewrite the identity
// file. Two interleaved rekeys share one staging path, so the second
// deletes the first's staged key while the first commits the vault to
// it, which destroys the only key able to read the vault. An exclusive
// advisory lock on a .lock sibling closes that window for rekey and
// passwd both. The kernel drops the lock when the process exits, so a
// crash never wedges a later run. The empty lock file is left in place
// on purpose: removing it would let a third process lock a fresh inode
// while the second still holds the old one.
func acquireIdentityLock(identityPath string) (func(), error) {
	// A missing parent directory means no identity was created here yet.
	// Surface the same not-found hint the identity load gives, rather
	// than a raw error about the lock file. The lock is taken before the
	// load, so without this a first-run passwd or rekey would report the
	// lock path instead of pointing at init.
	return flockExclusiveNB(
		identityLockPath(identityPath),
		fmt.Sprintf("another safetybox rekey or passwd is running against %s: retry when it finishes", identityPath),
		fmt.Errorf("%s: %w", identityPath, identity.ErrNotFound),
	)
}

// acquireMigrateLock serializes migrate against another migrate on the
// same vault. Two concurrent migrates otherwise both pass the format
// pre-check outside the write transaction, then the loser blocks on the
// SQLite write lock and can time out with a raw busy error rather than a
// clear message. An exclusive advisory lock on a .lock sibling of the
// vault closes that window, so the second migrate refuses up front the
// way a second rekey does. The kernel drops the lock when the process
// exits, so a crash never wedges a later run.
func acquireMigrateLock(vaultPath string) (func(), error) {
	return flockExclusiveNB(
		lockSiblingPath(vaultPath),
		fmt.Sprintf("another safetybox migrate is running against %s: retry when it finishes", vaultPath),
		fmt.Errorf("open %s: %w", vaultPath, vault.ErrVaultNotFound),
	)
}

// flockExclusiveNB opens lockFilePath and takes an exclusive,
// non-blocking advisory lock on it. It returns a release func that
// unlocks and closes. missingParent is returned when the lock file's
// parent directory does not exist, so the caller can surface a
// domain-specific hint instead of a raw lock error. busyMessage names
// the running operation for the case where another process already holds
// the lock. The empty lock file is left in place on release, so a third
// process cannot lock a fresh inode while a second still holds the old
// one.
func flockExclusiveNB(lockFilePath, busyMessage string, missingParent error) (func(), error) {
	lockFilePath = filepath.Clean(lockFilePath)

	file, err := os.OpenFile(lockFilePath, os.O_RDWR|os.O_CREATE, lockFileMode)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, missingParent
		}

		return nil, fmt.Errorf("open lock %s: %w", lockFilePath, err)
	}

	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()

		// EWOULDBLOCK is the one expected failure: another process holds
		// the lock. Anything else is an environment problem, such as a
		// filesystem without flock support, and must not masquerade as a
		// concurrent run.
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: %w", busyMessage, err)
		}

		return nil, fmt.Errorf("lock %s: %w", lockFilePath, err)
	}

	return func() {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
	}, nil
}

// identityLockPath derives the identity file's advisory lock path.
func identityLockPath(identityPath string) string {
	return lockSiblingPath(identityPath)
}

// lockSiblingPath derives an advisory lock path from a target file path.
// It resolves symlinks so two spellings of one target, such as a symlink
// alias, lock the same file and serialize against each other.
// EvalSymlinks needs the file to exist, so before the target is created
// it falls back to an absolute path, and finally to a cleaned path.
func lockSiblingPath(targetPath string) string {
	if resolved, err := filepath.EvalSymlinks(targetPath); err == nil {
		return resolved + ".lock"
	}

	if absolute, err := filepath.Abs(targetPath); err == nil {
		return absolute + ".lock"
	}

	return filepath.Clean(targetPath + ".lock")
}

// warnLooseVaultPerms warns once per invocation when the vault file,
// its directory, or its WAL siblings grant group or world access. It
// runs from PersistentPreRun, so it fires for whatever verb runs,
// including ones that never open the vault such as passwd, without
// threading a warning through each open. A resolve error is left to the
// verb itself to surface, and a missing vault, the normal case before
// init, produces no warning.
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
func (o *options) openVault(ctx context.Context) (*vault.Vault, error) {
	path, err := o.resolveVaultPath()
	if err != nil {
		return nil, err
	}

	opened, err := vault.Open(ctx, path)
	if err != nil {
		return nil, userHint(err)
	}

	return opened, nil
}

// storedRecipient reads and parses the vault's recipient. Write verbs
// need nothing else, which is the point of the asymmetric model.
func storedRecipient(ctx context.Context, openedVault *vault.Vault) (*age.X25519Recipient, error) {
	stored, err := openedVault.Recipient(ctx)
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
//
// explicit selects how a metadata mismatch is reported. An explicitly
// named secret fails loud, matching get, so a caller who asked for one
// secret by name learns it is unreadable. A batch selection, exec or a
// reveal filter, skips the one mismatching secret with a warning and
// delivers the rest, the way NUL bytes and invalid env names are
// already handled. A benign disable after a metadata change lands here,
// so one such secret must not take down the whole run. A decrypt or
// framing failure always fails loud, since that signals corruption or a
// downgrade attempt, not a benign metadata edit.
func forEachDecrypted(cobraCmd *cobra.Command, opts *options, expectedRecipient string, entries []vault.Entry,
	explicit bool, visit func(entry vault.Entry, expired bool, value secret.Value) error,
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

		value, bound, err := envelope.Open(key, address, entry.Envelope)
		if err != nil {
			return fmt.Errorf("open %s: %w", entry.Name, userHint(err))
		}

		if err := verifyBound(entry.EnvNameValid, entry.EnvName, entry.ExpiresAt, bound); err != nil {
			value.Destroy()

			if explicit {
				return fmt.Errorf("verify %s: %w", entry.Name, err)
			}

			printStderr(cobraCmd, fmt.Sprintf(
				"warning: secret %s metadata does not match the sealed value, skipped\n", entry.Name,
			))

			continue
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
	ctx := cobraCmd.Context()

	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return nil, err
	}

	newest, err := openedVault.NewestEnabled(ctx, name)

	recipient, recipientErr := openedVault.Recipient(ctx)

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

	value, bound, err := envelope.Open(key, address, newest.Envelope)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, userHint(err))
	}

	envNameValid := newest.Secret.EnvName != nil

	envName := ""
	if envNameValid {
		envName = *newest.Secret.EnvName
	}

	if err := verifyBound(envNameValid, envName, newest.Secret.ExpiresAt, bound); err != nil {
		value.Destroy()

		return nil, fmt.Errorf("verify %s: %w", name, err)
	}

	if newest.Secret.Expired(nowUTC()) {
		warnExpired(cobraCmd, name, newest.Secret.ExpiresAt)
	}

	return &resolved{meta: newest.Secret, version: newest.Version, value: value}, nil
}

// verifyBound refuses when the metadata sealed into the envelope does
// not match the plaintext columns the vault holds. A vault-write
// attacker who edits a column without re-sealing the value is caught
// here, since re-sealing needs the plaintext they do not have. An
// attacker who re-forges the whole envelope with matching metadata
// still passes, which is the documented limit of keyless writes.
//
// envNameValid reports whether the env name column is non-NULL. The
// store maps an empty env name to NULL and never writes a present empty
// string, and the frame cannot represent one distinctly from none, so a
// valid-but-empty column is treated as tampering.
func verifyBound(envNameValid bool, envName string, expiresAt *time.Time, bound envelope.Bound) error {
	if envNameValid && envName == "" {
		return fmt.Errorf("%w: env name column is present but empty", ErrMetadataTampered)
	}

	if bound.EnvName != envName {
		return fmt.Errorf("%w: env name mismatch", ErrMetadataTampered)
	}

	if (bound.ExpiresAt == "") != (expiresAt == nil) {
		return fmt.Errorf("%w: expiry mismatch", ErrMetadataTampered)
	}

	if expiresAt != nil {
		sealed, err := time.Parse(time.RFC3339, bound.ExpiresAt)
		if err != nil || !sealed.Equal(*expiresAt) {
			return fmt.Errorf("%w: expiry mismatch", ErrMetadataTampered)
		}
	}

	return nil
}
