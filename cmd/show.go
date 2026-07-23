package cmd

import (
	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"github.com/spf13/cobra"
)

// showOutput is metadata only. It never carries the value, its
// length, or anything derived from the plaintext.
type showOutput struct {
	vault.SecretMeta

	Expired  bool                `json:"expired"`
	Versions []vault.VersionMeta `json:"versions"`
}

func newShowCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Print a secret's metadata, never its value",
		Long: "show prints existence, timestamps, expiry state, and version " +
			"history. It needs no identity and decrypts nothing.",
		Args: cobra.ExactArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runShow(cobraCmd, opts, args[0])
		},
	}
}

func runShow(cobraCmd *cobra.Command, opts *options, name string) error {
	ctx := cobraCmd.Context()

	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	meta, versions, err := openedVault.Meta(ctx, name)
	if err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, showOutput{
		SecretMeta: meta,
		Expired:    meta.Expired(nowUTC()),
		Versions:   versions,
	})
}
