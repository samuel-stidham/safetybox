package cmd

import (
	"github.com/spf13/cobra"
)

func newDeleteCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Soft-delete a secret",
		Long: "delete hides the secret from list and get. Versions and " +
			"envelopes stay intact. set revives it, purge destroys it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runDelete(cobraCmd, opts, args[0])
		},
	}
}

func runDelete(cobraCmd *cobra.Command, opts *options, name string) error {
	openedVault, err := opts.openVault()
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	if err := openedVault.SoftDelete(name); err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, lifecycleOutput{Name: name, Result: "deleted"})
}
