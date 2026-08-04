package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/samuel-stidham/safetybox/v4/internal/envelope"
	"github.com/samuel-stidham/safetybox/v4/internal/vault"

	"filippo.io/age"
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

	// Refuse a missing vault before taking the lock. Locking first created
	// a stray empty vault.db.lock beside nothing, in a directory that
	// happened to exist, and nothing ever removed it. Lock files are
	// permanent by design once a vault exists, so deleting it afterwards
	// is not an option: that would reopen the fresh-inode race the design
	// avoids.
	if err := requireVaultFile(vaultPath); err != nil {
		return userHint(err)
	}

	// Serialize against another migrate on the same vault before loading
	// the identity or opening a write transaction. Without this, two
	// concurrent migrates both pass the format pre-check, then the loser
	// blocks on the write lock and can time out with a raw busy error
	// rather than the clear refusal this gives.
	unlock, err := acquireMigrateLock(vaultPath)
	if err != nil {
		return userHint(err)
	}

	defer unlock()

	// Re-sealing must decrypt every value, so migrate needs the identity.
	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return err
	}

	defer cleanup()

	recipient := key.Recipient()

	count, err := vault.Migrate(ctx, vaultPath, recipient.String(), newMigrateResealer(key, recipient))
	if errors.Is(err, vault.ErrAlreadyCurrentFormat) {
		return repairStragglers(cobraCmd, opts, vaultPath, key, recipient)
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

// repairStragglers runs on a vault that is already at the current
// format. It looks for version 1 envelopes a 2.x binary stranded by
// writing during a migration, and re-seals any it finds.
//
// Before this, an already-current vault made migrate stop, so a stranded
// row failed every read with a tamper-shaped error and no tool could fix
// it. The healthy case still reports nothing to do, and pays one decrypt
// per envelope to prove it.
func repairStragglers(
	cobraCmd *cobra.Command, opts *options, vaultPath string,
	key *age.X25519Identity, recipient *age.X25519Recipient,
) error {
	repaired, err := vault.RepairLegacyEnvelopes(
		cobraCmd.Context(), vaultPath, recipient.String(),
		newStragglerResealer(key, recipient),
	)
	if err != nil {
		return userHint(err)
	}

	if repaired == 0 {
		slog.Info("vault is already at the current format, nothing to migrate")

		return nil
	}

	slog.Info("repaired values left in the old format by an older safetybox writing during a migration",
		"count", repaired)

	return printJSON(cobraCmd, opts, migrateOutput{MigratedVersions: repaired, Result: "repaired"})
}

// newStragglerResealer wraps the migration resealer with the check that
// tells a stranded legacy row from a healthy one. A row that opens in the
// current format reports ErrEnvelopeCurrent, which the vault layer treats
// as nothing to do rather than as a failure.
func newStragglerResealer(key *age.X25519Identity, recipient age.Recipient) vault.MigrationResealer {
	migrateReseal := newMigrateResealer(key, recipient)

	return func(name string, number int64, envName, expiresAt string, oldEnvelope []byte) ([]byte, string, error) {
		address := vault.CanonicalAddress(name, number)

		value, _, err := envelope.Open(key, address, oldEnvelope)
		if err == nil {
			value.Destroy()

			return nil, "", vault.ErrEnvelopeCurrent
		}

		// Only a genuine version 1 frame is repairable here. A decrypt
		// failure or a real address mismatch is corruption or tampering,
		// and must keep failing loudly rather than be re-sealed.
		if !errors.Is(err, envelope.ErrLegacyEnvelope) {
			return nil, "", userHint(err)
		}

		return migrateReseal(name, number, envName, expiresAt, oldEnvelope)
	}
}

// newMigrateResealer builds the reseal callback the vault layer calls
// for each version during migration. It decrypts the legacy envelope
// with the loaded identity and re-seals the value into the current
// frame. It sanitizes a legacy env name the new frame cannot carry,
// warns naming the secret, and returns the env name it actually sealed
// so the vault layer can reconcile the shared column.
func newMigrateResealer(key *age.X25519Identity, recipient age.Recipient) vault.MigrationResealer {
	return func(name string, number int64, envName, expiresAt string, oldEnvelope []byte) ([]byte, string, error) {
		address := vault.CanonicalAddress(name, number)

		value, err := envelope.OpenLegacy(key, address, oldEnvelope)
		if err != nil {
			// OpenLegacy already prefixes the address, and the vault layer
			// prefixes the secret and version, so wrap no further.
			return nil, "", userHint(err)
		}

		defer value.Destroy()

		sealedEnvName, changed := frameSafeEnvName(envName)
		if changed {
			slog.Warn("secret env name had a newline the new format cannot store, "+
				"re-set it with --env-name if you need a different one",
				"name", name, "stored_as", sealedEnvName)
		}

		bound := envelope.Bound{EnvName: sealedEnvName, ExpiresAt: expiresAt}

		sealed, err := envelope.Seal(recipient, address, bound, value)
		if err != nil {
			return nil, "", userHint(err)
		}

		return sealed, sealedEnvName, nil
	}
}
