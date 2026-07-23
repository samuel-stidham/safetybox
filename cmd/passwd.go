package cmd

import (
	"github.com/samuel-stidham/safetybox/v2/internal/identity"

	"github.com/spf13/cobra"
)

func newPasswdCmd(opts *options) *cobra.Command {
	var newPassphraseFile string

	passwdCmd := &cobra.Command{
		Use:   "passwd",
		Short: "Change the identity passphrase",
		Long: "passwd decrypts the identity with the current passphrase and " +
			"re-encrypts it with a new one. The key itself does not change, " +
			"so the vault is untouched.",
		Args: cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return runPasswd(cobraCmd, opts, newPassphraseFile)
		},
	}

	passwdCmd.Flags().StringVar(&newPassphraseFile, "new-passphrase-file", "",
		"read the new passphrase from this file instead of prompting")

	return passwdCmd
}

func runPasswd(cobraCmd *cobra.Command, opts *options, newPassphraseFile string) error {
	identityPath, err := opts.resolveIdentityPath()
	if err != nil {
		return err
	}

	// Serialize against rekey and other passwd runs. An interleaved
	// passwd can overwrite an identity a rekey just promoted, so both
	// verbs share one lock for their whole run.
	unlock, err := acquireIdentityLock(identityPath)
	if err != nil {
		return userHint(err)
	}

	defer unlock()

	// Heal a rekey that crashed mid-swap, like every other verb that
	// loads the identity. Without this, passwd reports the identity
	// missing and hints at init while the live key sits at .new.
	if err := completeInterruptedRekey(identityPath); err != nil {
		return err
	}

	current, err := readPassphrase(cobraCmd, opts.passphraseFile, "Current passphrase: ")
	if err != nil {
		return err
	}

	defer zeroBytes(current)

	key, cleanup, err := identity.Load(identityPath, current)
	if err != nil {
		return userHint(err)
	}

	defer cleanup()

	fresh, err := readNewPassphrase(cobraCmd, newPassphraseFile, "New passphrase: ")
	if err != nil {
		return err
	}

	defer zeroBytes(fresh)

	if err := identity.Replace(identityPath, key, fresh); err != nil {
		return userHint(err)
	}

	printStderr(cobraCmd, "passphrase changed for "+identityPath+"\n")

	return nil
}
