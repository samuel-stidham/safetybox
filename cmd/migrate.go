package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/samuel-stidham/safetybox/v3/internal/envelope"
	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"github.com/spf13/cobra"
)

type migrateOutput struct {
	MigratedVersions int64  `json:"migratedVersions"`
	Result           string `json:"result"`
}

// frameSafeEnvName removes the characters the envelope frame cannot
// carry from a legacy env name, which today is the newline. A vault from
// before set validated env names could store one with a newline, and
// [envelope.Seal] refuses it. The migration strips it so the upgrade can
// complete, and reports whether it changed anything so the caller can
// warn. A trailing-newline env name, the common case, becomes the name
// the user meant.
func frameSafeEnvName(envName string) (string, bool) {
	clean := strings.ReplaceAll(envName, "\n", "")
	clean = strings.ReplaceAll(clean, "\r", "")

	return clean, clean != envName
}

func newMigrateCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Upgrade an older vault to the current format",
		Long: "migrate re-seals every secret into the current envelope format, " +
			"which binds the env name and expiry into each value so a later " +
			"metadata edit is detectable on read. It needs your passphrase, " +
			"because re-sealing decrypts each value. The identity and the " +
			"recipient do not change. Back up the vault file first.",
		Args: cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return runMigrate(cobraCmd, opts)
		},
	}
}

func runMigrate(cobraCmd *cobra.Command, opts *options) error {
	ctx := cobraCmd.Context()

	vaultPath, err := opts.resolveVaultPath()
	if err != nil {
		return err
	}

	// Re-sealing must decrypt every value, so migrate needs the identity.
	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return err
	}

	defer cleanup()

	recipient := key.Recipient()

	count, err := vault.Migrate(ctx, vaultPath, recipient.String(),
		func(name string, number int64, envName, expiresAt string, oldEnvelope []byte) ([]byte, string, error) {
			address := vault.CanonicalAddress(name, number)

			value, err := envelope.OpenLegacy(key, address, oldEnvelope)
			if err != nil {
				// OpenLegacy already prefixes the address, and the vault
				// layer prefixes the secret and version, so wrap no further.
				return nil, "", userHint(err)
			}

			defer value.Destroy()

			sealedEnvName, changed := frameSafeEnvName(envName)
			if changed {
				printStderr(cobraCmd, fmt.Sprintf(
					"warning: secret %s had an env name with a newline the new format cannot store, "+
						"stored as %q, re-set it with --env-name if you need a different one\n",
					name, sealedEnvName,
				))
			}

			bound := envelope.Bound{EnvName: sealedEnvName, ExpiresAt: expiresAt}

			sealed, err := envelope.Seal(recipient, address, bound, value)
			if err != nil {
				return nil, "", userHint(err)
			}

			return sealed, sealedEnvName, nil
		})
	if errors.Is(err, vault.ErrAlreadyCurrentFormat) {
		printStderr(cobraCmd, "vault is already at the current format, nothing to migrate\n")

		return nil
	}

	if errors.Is(err, vault.ErrFormatVersion) {
		// The generic hint would say to run migrate, the command that just
		// failed. A format newer than this build understands needs a newer
		// binary, not another migrate.
		return fmt.Errorf("%w: upgrade safetybox to open a vault in a newer format", err)
	}

	if err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, migrateOutput{MigratedVersions: count, Result: "migrated"})
}
