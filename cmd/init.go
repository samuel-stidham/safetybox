package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/samuel-stidham/safetybox/v2/internal/envelope"
	"github.com/samuel-stidham/safetybox/v2/internal/identity"
	"github.com/samuel-stidham/safetybox/v2/internal/secret"
	"github.com/samuel-stidham/safetybox/v2/internal/vault"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

const initVerb = "init"

func newInitCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   initVerb,
		Short: "Create a new identity and vault",
		Long: "init generates an X25519 identity, encrypts it with a passphrase, " +
			"creates the vault, and runs a seal/open self-test.",
		Args: cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return runInit(cobraCmd, opts)
		},
	}
}

func runInit(cobraCmd *cobra.Command, opts *options) error {
	ctx := cobraCmd.Context()

	identityPath, err := opts.resolveIdentityPath()
	if err != nil {
		return err
	}

	vaultPath, err := opts.resolveVaultPath()
	if err != nil {
		return err
	}

	switch _, err := os.Stat(identityPath); {
	case err == nil:
		return fmt.Errorf("identity already exists at %s: refusing to overwrite it, move it aside first", identityPath)
	case !errors.Is(err, fs.ErrNotExist):
		// A permission or path error is not a green light to create.
		return fmt.Errorf("stat identity %s: %w", identityPath, err)
	}

	passphrase, err := readNewPassphrase(cobraCmd, opts.passphraseFile, "Passphrase for the new identity: ")
	if err != nil {
		return err
	}

	defer zeroBytes(passphrase)

	key, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}

	if err := identity.Write(identityPath, key, passphrase); err != nil {
		return userHint(err)
	}

	if err := vault.Create(ctx, vaultPath, key.Recipient().String()); err != nil {
		// The identity was written this invocation and guards
		// nothing yet, so remove it to keep init retryable.
		_ = os.Remove(identityPath)

		return userHint(fmt.Errorf("create vault: %w", err))
	}

	if err := selfTest(ctx, vaultPath, key); err != nil {
		// Both files were created this invocation and guard nothing,
		// so remove them rather than wedge a re-run on ErrExists.
		_ = os.Remove(identityPath)

		vault.RemoveFiles(vaultPath)

		return fmt.Errorf("self-test: %w", err)
	}

	printInitSuccess(cobraCmd, identityPath, vaultPath, key.Recipient().String())

	return nil
}

// selfTest seals and opens one throwaway value through the full
// stack: vault recipient read-back, envelope seal, envelope open.
func selfTest(ctx context.Context, vaultPath string, key *age.X25519Identity) error {
	openedVault, err := vault.Open(ctx, vaultPath)
	if err != nil {
		return fmt.Errorf("open new vault: %w", err)
	}

	defer func() { _ = openedVault.Close() }()

	recipient, err := storedRecipient(ctx, openedVault)
	if err != nil {
		return err
	}

	const probeAddress = "api/v1/safetybox/self-test/1"

	probe := []byte("safetybox-init-self-test-probe")

	sealed, err := envelope.Seal(recipient, probeAddress, secret.New(probe))
	if err != nil {
		return fmt.Errorf("seal probe: %w", err)
	}

	opened, err := envelope.Open(key, probeAddress, sealed)
	if err != nil {
		return fmt.Errorf("open probe: %w", err)
	}

	defer opened.Destroy()

	if !bytes.Equal(opened.Expose(), probe) {
		return errors.New("round-trip produced different bytes")
	}

	return nil
}

func printInitSuccess(cobraCmd *cobra.Command, identityPath, vaultPath, recipient string) {
	lines := []string{
		"safetybox initialized",
		"",
		"  identity:  " + identityPath,
		"  vault:     " + vaultPath,
		"  recipient: " + recipient,
		"",
		"BACK UP THE IDENTITY FILE NOW.",
		"Without it every secret in this vault is unrecoverable.",
		"The passphrase alone cannot recover them. Copy",
		"  " + identityPath,
		"somewhere safe and offline.",
	}

	for _, line := range lines {
		printStderr(cobraCmd, line+"\n")
	}
}
