package cmd

import (
	"time"

	"github.com/samuel-stidham/safetybox/internal/secret"
	"github.com/samuel-stidham/safetybox/internal/vault"

	"github.com/spf13/cobra"
)

// getOutput carries the value as a secret.Value, so JSON encoding
// renders [REDACTED] by construction. Only reveal exposes plaintext.
type getOutput struct {
	Name      string       `json:"name"`
	Version   int64        `json:"version"`
	State     vault.State  `json:"state"`
	EnvName   *string      `json:"envName,omitempty"`
	CreatedAt time.Time    `json:"createdAt"`
	UpdatedAt time.Time    `json:"updatedAt"`
	ExpiresAt *time.Time   `json:"expiresAt,omitempty"`
	Expired   bool         `json:"expired"`
	Value     secret.Value `json:"value"`
}

func newGetCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Fetch and verify the newest enabled version of a secret",
		Long: "get decrypts the newest enabled version, verifies its address " +
			"binding, and prints metadata with the value redacted. Use " +
			"reveal to display the plaintext.",
		Args: cobra.ExactArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runGet(cobraCmd, opts, args[0])
		},
	}
}

func runGet(cobraCmd *cobra.Command, opts *options, name string) error {
	result, err := resolveNewest(cobraCmd, opts, name)
	if err != nil {
		return err
	}

	return printJSON(cobraCmd, opts, getOutput{
		Name:      result.meta.Name,
		Version:   result.version.Number,
		State:     result.version.State,
		EnvName:   result.meta.EnvName,
		CreatedAt: result.meta.CreatedAt,
		UpdatedAt: result.meta.UpdatedAt,
		ExpiresAt: result.meta.ExpiresAt,
		Expired:   result.meta.Expired(nowUTC()),
		Value:     result.value,
	})
}
