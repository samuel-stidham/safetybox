package cmd

import (
	"github.com/samuel-stidham/safetybox/v2/internal/vault"

	"github.com/spf13/cobra"
)

// listEntry adds the computed expiry state to a stored summary.
type listEntry struct {
	vault.Summary

	Expired bool `json:"expired"`
}

func newListCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list [prefix]",
		Short: "List secrets, optionally under a name prefix",
		Long: "list prints metadata for every non-deleted secret. Names are " +
			"plaintext columns in the MVP, so no identity is needed.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			prefix := ""
			if len(args) == 1 {
				prefix = args[0]
			}

			return runList(cobraCmd, opts, prefix)
		},
	}
}

func runList(cobraCmd *cobra.Command, opts *options, prefix string) error {
	ctx := cobraCmd.Context()

	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	summaries, err := openedVault.List(ctx, prefix)
	if err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, toListEntries(summaries))
}

func toListEntries(summaries []vault.Summary) []listEntry {
	now := nowUTC()
	entries := make([]listEntry, 0, len(summaries))

	for _, summary := range summaries {
		entries = append(entries, listEntry{Summary: summary, Expired: summary.Expired(now)})
	}

	return entries
}
