package cmd

import (
	"fmt"
	"strconv"

	"github.com/samuel-stidham/safetybox/internal/vault"

	"github.com/spf13/cobra"
)

type lifecycleOutput struct {
	Name    string `json:"name"`
	Version int64  `json:"version,omitempty"`
	Result  string `json:"result"`
}

// disableArgCount is the name plus the version number.
const disableArgCount = 2

func newDisableCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name> <version>",
		Short: "Disable a secret version",
		Long: "disable takes one version out of resolution without touching " +
			"its envelope. get resolves the newest remaining enabled version.",
		Args: cobra.ExactArgs(disableArgCount),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			number, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("version must be a number, got %q", args[1])
			}

			return runDisable(cobraCmd, opts, args[0], number)
		},
	}
}

func runDisable(cobraCmd *cobra.Command, opts *options, name string, number int64) error {
	openedVault, err := opts.openVault()
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	if err := openedVault.Disable(name, number); err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, lifecycleOutput{
		Name:    name,
		Version: number,
		Result:  string(vault.StateDisabled),
	})
}
