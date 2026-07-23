package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/samuel-stidham/safetybox/internal/envelope"
	"github.com/samuel-stidham/safetybox/internal/identity"
	"github.com/samuel-stidham/safetybox/internal/vault"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

type rekeyOutput struct {
	Recipient       string `json:"recipient"`
	RekeyedVersions int64  `json:"rekeyedVersions"`
	BackupIdentity  string `json:"backupIdentity"`
}

func newRekeyCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "rekey",
		Short: "Rotate the identity and re-encrypt every live version",
		Long: "rekey generates a new identity, re-encrypts every " +
			"non-destroyed version to it inside one transaction, and swaps " +
			"the identity file. The old identity is kept as a .bak sibling. " +
			"The passphrase stays the same, use passwd to change it.",
		Args: cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return runRekey(cobraCmd, opts)
		},
	}
}

func runRekey(cobraCmd *cobra.Command, opts *options) error {
	identityPath, err := opts.resolveIdentityPath()
	if err != nil {
		return err
	}

	// Heal a prior rekey that crashed mid-swap before doing anything
	// else, so the load below sees a real identity file.
	if err := completeInterruptedRekey(identityPath); err != nil {
		return err
	}

	passphrase, err := readPassphrase(cobraCmd, opts.passphraseFile, "Passphrase: ")
	if err != nil {
		return err
	}

	defer zeroBytes(passphrase)

	oldKey, cleanup, err := identity.Load(identityPath, passphrase)
	if err != nil {
		return userHint(err)
	}

	defer cleanup()

	stagedPath := identityPath + ".new"

	// Refuse to touch anything unless the vault is really encrypted to
	// the loaded identity. A previous rekey that committed the vault
	// but crashed before the identity swap leaves the OLD key at
	// identityPath, loading cleanly, while the only key that can read
	// the vault sits at the staged sibling. Deleting that staged file
	// as "stale" would destroy every secret forever.
	if err := ensureVaultOnIdentity(opts, oldKey, identityPath, stagedPath); err != nil {
		return err
	}

	newKey, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate new identity: %w", err)
	}

	// The new identity is written beside the old one BEFORE the vault
	// transaction, so a crash can never leave re-encrypted envelopes
	// without their key on disk.
	if err := stageNewIdentity(stagedPath, newKey, passphrase); err != nil {
		return err
	}

	count, err := rekeyVault(cobraCmd, opts, oldKey, newKey)
	if err != nil {
		_ = os.Remove(stagedPath)

		return err
	}

	if err := swapIdentityFiles(identityPath, stagedPath); err != nil {
		return err
	}

	return printJSON(cobraCmd, opts, rekeyOutput{
		Recipient:       newKey.Recipient().String(),
		RekeyedVersions: count,
		BackupIdentity:  identityPath + ".bak",
	})
}

// ensureVaultOnIdentity verifies the vault's stored recipient matches
// the loaded identity before rekey stages or removes anything. A
// clean identity load only proves the passphrase. It does not prove
// the vault is on that key: a rekey that committed the vault and then
// crashed before the swap leaves the old key in place and the live
// key at the staged sibling.
func ensureVaultOnIdentity(opts *options, oldKey *age.X25519Identity, identityPath, stagedPath string) error {
	openedVault, err := opts.openVault()
	if err != nil {
		return err
	}

	stored, err := openedVault.Recipient()

	_ = openedVault.Close()

	if err != nil {
		return fmt.Errorf("read stored recipient: %w", err)
	}

	if stored == oldKey.Recipient().String() {
		return nil
	}

	_, statErr := os.Stat(stagedPath)

	switch {
	case statErr == nil:
		return fmt.Errorf(
			"the vault is not encrypted to the identity at %s: a previous rekey likely crashed after re-encrypting the vault, "+
				"and %s is the live key: back it up, then move it to %s and retry",
			identityPath, stagedPath, identityPath,
		)
	case !errors.Is(statErr, fs.ErrNotExist):
		// A staged key that cannot even be inspected must not be
		// reported as absent. The refusal has to name the real problem.
		return fmt.Errorf("stat staged identity %s: %w", stagedPath, statErr)
	}

	return fmt.Errorf("the vault is not encrypted to the identity at %s: refusing to rekey", identityPath)
}

// stageNewIdentity writes the new identity to its .new sibling before
// the vault transaction. A leftover .new from an earlier crashed
// rekey is removed first: ensureVaultOnIdentity proved the vault is
// on the loaded key, so the staged file is a stale staging artifact,
// not a live key. A removal failure other than "already gone" is
// surfaced, so a permission problem is reported plainly instead of
// resurfacing as a confusing ErrExists from Write.
func stageNewIdentity(stagedPath string, newKey *age.X25519Identity, passphrase []byte) error {
	if err := os.Remove(stagedPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale staged identity %s: %w", stagedPath, err)
	}

	if err := identity.Write(stagedPath, newKey, passphrase); err != nil {
		return userHint(err)
	}

	return nil
}

func rekeyVault(cobraCmd *cobra.Command, opts *options, oldKey, newKey *age.X25519Identity) (int64, error) {
	openedVault, err := opts.openVault()
	if err != nil {
		return 0, err
	}

	defer func() { _ = openedVault.Close() }()

	count, err := openedVault.Rekey(newKey.Recipient().String(),
		func(name string, number int64, blob []byte) ([]byte, error) {
			address := vault.CanonicalAddress(name, number)

			value, err := envelope.Open(oldKey, address, blob)
			if err != nil {
				return nil, fmt.Errorf("open %s: %w", address, err)
			}

			// Wipe each decrypted value as soon as it is resealed, so a
			// rekey does not hold every secret's plaintext on the heap
			// for the length of the whole rotation.
			defer value.Destroy()

			resealed, err := envelope.Seal(newKey.Recipient(), address, value)
			if err != nil {
				return nil, fmt.Errorf("reseal %s: %w", address, err)
			}

			return resealed, nil
		})
	if err != nil {
		return 0, userHint(err)
	}

	warnIfCheckpointBlocked(cobraCmd, openedVault)

	return count, nil
}

// swapIdentityFiles moves the old identity to .bak and the staged new
// identity into place. The vault is already rekeyed at this point, so
// on failure the error says exactly where the new identity lives.
func swapIdentityFiles(identityPath, stagedPath string) error {
	backupPath := identityPath + ".bak"

	if err := os.Rename(identityPath, backupPath); err != nil {
		return fmt.Errorf("vault rekeyed but identity swap failed, your NEW identity is at %s: %w", stagedPath, err)
	}

	if err := os.Rename(stagedPath, identityPath); err != nil {
		return fmt.Errorf("vault rekeyed but identity swap failed, your NEW identity is at %s: %w", stagedPath, err)
	}

	// fsync the directory so both renames are durable. Without it, a
	// power loss after rekey reports success could revert the swap,
	// leaving the old key in place while the vault stays on the new
	// one. The swap already happened, so a sync failure must say so.
	if err := identity.SyncDir(filepath.Dir(identityPath)); err != nil {
		return fmt.Errorf("rekey complete and the new identity is in place, but the swap is not yet durable: %w", err)
	}

	return nil
}
