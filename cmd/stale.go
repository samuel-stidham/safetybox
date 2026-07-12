package cmd

import (
	"github.com/spf13/cobra"
)

func newStaleCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "stale",
		Short: "List secrets past their expiry",
		Long: "stale lists secrets whose expiry has passed. They still " +
			"resolve. Expiry is a staleness flag, never a deletion trigger.",
		Args: cobra.NoArgs,
		RunE: func(cobraCmd *cobra.Command, _ []string) error {
			return runStale(cobraCmd, opts)
		},
	}
}

func runStale(cobraCmd *cobra.Command, opts *options) error {
	openedVault, err := opts.openVault()
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	summaries, err := openedVault.Stale(nowUTC())
	if err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, toListEntries(summaries))
}
