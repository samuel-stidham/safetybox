package cmd

import (
	"fmt"
	"os"

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

	newKey, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate new identity: %w", err)
	}

	// The new identity is written beside the old one BEFORE the vault
	// transaction, so a crash can never leave re-encrypted envelopes
	// without their key on disk.
	stagedPath := identityPath + ".new"

	if err := identity.Write(stagedPath, newKey, passphrase); err != nil {
		return userHint(err)
	}

	count, err := rekeyVault(opts, oldKey, newKey)
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

func rekeyVault(opts *options, oldKey, newKey *age.X25519Identity) (int64, error) {
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

			resealed, err := envelope.Seal(newKey.Recipient(), address, value)
			if err != nil {
				return nil, fmt.Errorf("reseal %s: %w", address, err)
			}

			return resealed, nil
		})
	if err != nil {
		return 0, userHint(err)
	}

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

	return nil
}
