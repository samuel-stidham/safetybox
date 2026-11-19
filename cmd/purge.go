package cmd

import (
	"context"
	"errors"
	"log/slog"

	"github.com/samuel-stidham/safetybox/v4/internal/vault"

	"github.com/spf13/cobra"
)

type purgeOutput struct {
	Name      string `json:"name"`
	Destroyed int64  `json:"destroyedVersions"`
	Result    string `json:"result"`
}

func newPurgeCmd(opts *options) *cobra.Command {
	var yes bool

	purgeCmd := &cobra.Command{
		Use:   "purge <name>",
		Short: "Destroy a secret's envelopes forever",
		Long: "purge erases every envelope of the secret and marks all " +
			"versions destroyed. The values are gone forever. Rows and " +
			"history remain, so the secret name stays readable in the " +
			"vault forever, even after purge. It requires --yes.",
		Args: exactArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			if !yes {
				return errors.New("purge destroys envelopes forever: re-run with --yes to confirm")
			}

			return runPurge(cobraCmd, opts, args[0])
		},
	}

	purgeCmd.Flags().BoolVar(&yes, "yes", false, "confirm the irreversible destruction")

	return purgeCmd
}

func runPurge(cobraCmd *cobra.Command, opts *options, name string) error {
	ctx := cobraCmd.Context()

	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	destroyed, err := openedVault.Purge(ctx, name)
	if err != nil {
		return userHint(err)
	}

	warnIfCheckpointBlocked(ctx, openedVault)

	return printJSON(cobraCmd, opts, purgeOutput{Name: name, Destroyed: destroyed, Result: "purged"})
}

// warnIfCheckpointBlocked retries the WAL scrub and warns when it
// cannot happen. A blocked checkpoint gets the concurrent-reader
// explanation. Any other failure prints the real error, so an I/O or
// permission problem is not misattributed to another process. The
// destructive operation is already committed, so this is advice,
// never a failure: the erased bytes stay recoverable from WAL frames
// until a later checkpoint truncates them.
func warnIfCheckpointBlocked(ctx context.Context, openedVault *vault.Vault) {
	err := openedVault.Checkpoint(ctx)
	if err == nil {
		return
	}

	if errors.Is(err, vault.ErrCheckpointBlocked) {
		slog.Warn("another safetybox process is reading the vault, old ciphertext " +
			"may linger in the write-ahead log until the next checkpoint")

		return
	}

	slog.Warn("could not scrub the write-ahead log", "error", err)
}
