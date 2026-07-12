package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

// revealOutput is the ONLY output shape in this codebase carrying
// plaintext. Its Value field is a plain string filled through
// secret.Value.Expose, the single deliberate display exit.
type revealOutput struct {
	Name      string     `json:"name"`
	Version   int64      `json:"version"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Expired   bool       `json:"expired"`
	Value     string     `json:"value"`
}

func newRevealCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "reveal <name>",
		Short: "Deliberately print a secret's plaintext value",
		Long: "reveal is the single verb that displays plaintext. Everything " +
			"else redacts. Pipe with --json and extract .value for scripts.",
		Args: cobra.ExactArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runReveal(cobraCmd, opts, args[0])
		},
	}
}

func runReveal(cobraCmd *cobra.Command, opts *options, name string) error {
	result, err := resolveNewest(cobraCmd, opts, name)
	if err != nil {
		return err
	}

	return printJSON(cobraCmd, opts, revealOutput{
		Name:      result.meta.Name,
		Version:   result.version.Number,
		ExpiresAt: result.meta.ExpiresAt,
		Expired:   result.meta.Expired(nowUTC()),
		// The one deliberate plaintext display in safetybox.
		Value: string(result.value.Expose()),
	})
}
