package cmd

import (
	"errors"

	"github.com/samuel-stidham/safetybox/internal/vault"

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
			"versions destroyed. Rows and history remain, the values are " +
			"gone forever. It requires --yes.",
		Args: cobra.ExactArgs(1),
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
	openedVault, err := opts.openVault()
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	destroyed, err := openedVault.Purge(name)
	if err != nil {
		return userHint(err)
	}

	warnIfCheckpointBlocked(cobraCmd, openedVault)

	return printJSON(cobraCmd, opts, purgeOutput{Name: name, Destroyed: destroyed, Result: "purged"})
}

// warnIfCheckpointBlocked retries the WAL scrub and warns when it
// cannot happen. A blocked checkpoint gets the concurrent-reader
// explanation. Any other failure prints the real error, so an I/O or
// permission problem is not misattributed to another process. The
// destructive operation is already committed, so this is advice,
// never a failure: the erased bytes stay recoverable from WAL frames
// until a later checkpoint truncates them.
func warnIfCheckpointBlocked(cobraCmd *cobra.Command, openedVault *vault.Vault) {
	err := openedVault.Checkpoint()
	if err == nil {
		return
	}

	if errors.Is(err, vault.ErrCheckpointBlocked) {
		printStderr(cobraCmd,
			"warning: another safetybox process is reading the vault, old ciphertext "+
				"may linger in the write-ahead log until the next checkpoint\n")

		return
	}

	printStderr(cobraCmd, "warning: could not scrub the write-ahead log: "+err.Error()+"\n")
}
