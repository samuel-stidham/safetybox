package cmd

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/samuel-stidham/safetybox/internal/envelope"
	"github.com/samuel-stidham/safetybox/internal/vault"

	"github.com/spf13/cobra"
)

// The reveal output formats. json is the default. sh and fish emit
// assignment lines ready to source into a shell session.
const (
	formatJSON = "json"
	formatSh   = "sh"
	formatFish = "fish"
)

// revealOutput is the ONLY output shape in this codebase carrying
// plaintext. Its Value field is a plain string filled through
// secret.Value.Expose, the single deliberate display exit.
type revealOutput struct {
	Name      string     `json:"name"`
	EnvName   *string    `json:"envName,omitempty"`
	Version   int64      `json:"version"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Expired   bool       `json:"expired"`
	Value     string     `json:"value"`
}

// revealFlags carries the reveal verb's flag values.
type revealFlags struct {
	env    bool
	prefix string
	format string
}

// revealItem is one selected secret before decryption. envName is
// empty when the secret has none.
type revealItem struct {
	name      string
	envName   string
	version   int64
	expiresAt *time.Time
	envelope  []byte
}

func newRevealCmd(opts *options) *cobra.Command {
	var flags revealFlags

	revealCmd := &cobra.Command{
		Use:   "reveal [name]... [--env] [--prefix PREFIX] [--format json|sh|fish]",
		Short: "Deliberately print secrets' plaintext values",
		Long: "reveal is the single verb that displays plaintext. Everything " +
			"else redacts. One name prints one JSON object. Several names, " +
			"--env, or --prefix select a batch that decrypts with a single " +
			"passphrase read. --format sh or fish emits assignment lines " +
			"ready to source into a shell session.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			if err := validateRevealRequest(args, flags); err != nil {
				return err
			}

			return runReveal(cobraCmd, opts, args, flags)
		},
	}

	revealCmd.Flags().BoolVar(&flags.env, "env", false, "select every secret that has an env name")
	revealCmd.Flags().StringVar(&flags.prefix, "prefix", "", "select every secret under a name prefix")
	revealCmd.Flags().StringVar(&flags.format, "format", formatJSON, "output format: json, sh, or fish")

	return revealCmd
}

// validateRevealRequest rejects contradictory selections before any
// vault or identity work happens.
func validateRevealRequest(names []string, flags revealFlags) error {
	usingFilters := flags.env || flags.prefix != ""

	if len(names) > 0 && usingFilters {
		return errors.New("pass names or --env/--prefix filters, not both")
	}

	if len(names) == 0 && !usingFilters {
		return errors.New("pass at least one name, or select a set with --env or --prefix")
	}

	switch flags.format {
	case formatJSON, formatSh, formatFish:
		return nil
	default:
		return fmt.Errorf("--format %q is not json, sh, or fish", flags.format)
	}
}

func runReveal(cobraCmd *cobra.Command, opts *options, names []string, flags revealFlags) error {
	items, err := collectRevealItems(opts, names, flags)
	if err != nil {
		return err
	}

	outputs, err := decryptRevealItems(cobraCmd, opts, items)
	if err != nil {
		return err
	}

	if flags.format != formatJSON {
		return printShellAssignments(cobraCmd, outputs, flags.format)
	}

	// A single explicit name keeps the original one-object output
	// shape, so `reveal <name> --json | jq -r .value` stays stable.
	if len(names) == 1 {
		return printJSON(cobraCmd, opts, outputs[0])
	}

	return printJSON(cobraCmd, opts, outputs)
}

// collectRevealItems selects the secrets to decrypt. Explicit names
// resolve one by one so a missing or deleted name fails loudly.
// Filters select whatever matches, and matching nothing is fine.
func collectRevealItems(opts *options, names []string, flags revealFlags) ([]revealItem, error) {
	openedVault, err := opts.openVault()
	if err != nil {
		return nil, err
	}

	defer func() { _ = openedVault.Close() }()

	if len(names) > 0 {
		return itemsByName(openedVault, names)
	}

	entries, err := openedVault.Entries(vault.EntryFilter{Prefix: flags.prefix, EnvNamed: flags.env})
	if err != nil {
		return nil, userHint(err)
	}

	items := make([]revealItem, 0, len(entries))

	for _, entry := range entries {
		items = append(items, revealItem{
			name:      entry.Name,
			envName:   entry.EnvName,
			version:   entry.Version,
			expiresAt: entry.ExpiresAt,
			envelope:  entry.Envelope,
		})
	}

	return items, nil
}

func itemsByName(openedVault *vault.Vault, names []string) ([]revealItem, error) {
	items := make([]revealItem, 0, len(names))

	for _, name := range names {
		resolved, err := openedVault.NewestEnabled(name)
		if err != nil {
			return nil, userHint(err)
		}

		item := revealItem{
			name:      resolved.Secret.Name,
			version:   resolved.Version.Number,
			expiresAt: resolved.Secret.ExpiresAt,
			envelope:  resolved.Envelope,
		}

		if resolved.Secret.EnvName != nil {
			item.envName = *resolved.Secret.EnvName
		}

		items = append(items, item)
	}

	return items, nil
}

// decryptRevealItems unlocks the identity once and opens every
// envelope with it, so a batch pays the passphrase KDF a single time.
func decryptRevealItems(cobraCmd *cobra.Command, opts *options, items []revealItem) ([]revealOutput, error) {
	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	now := nowUTC()
	outputs := make([]revealOutput, 0, len(items))

	for _, item := range items {
		address := vault.CanonicalAddress(item.name, item.version)

		value, err := envelope.Open(key, address, item.envelope)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", item.name, userHint(err))
		}

		expired := item.expiresAt != nil && !now.Before(*item.expiresAt)
		if expired {
			warnExpired(cobraCmd, item.name, item.expiresAt)
		}

		output := revealOutput{
			Name:      item.name,
			Version:   item.version,
			ExpiresAt: item.expiresAt,
			Expired:   expired,
			// The one deliberate plaintext display in safetybox.
			Value: string(value.Expose()),
		}

		if item.envName != "" {
			envName := item.envName
			output.EnvName = &envName
		}

		outputs = append(outputs, output)
	}

	return outputs, nil
}

// printShellAssignments writes one assignment line per secret that
// carries a usable env name, and warns about the rest on stderr so a
// sourced batch never silently drops a secret.
func printShellAssignments(cobraCmd *cobra.Command, outputs []revealOutput, format string) error {
	for _, output := range outputs {
		if output.EnvName == nil {
			printStderr(cobraCmd, fmt.Sprintf("warning: secret %s has no env name, skipped\n", output.Name))

			continue
		}

		if !isShellIdentifier(*output.EnvName) {
			printStderr(cobraCmd, fmt.Sprintf(
				"warning: secret %s env name %q is not a shell identifier, skipped\n",
				output.Name, *output.EnvName,
			))

			continue
		}

		if _, err := fmt.Fprintln(cobraCmd.OutOrStdout(), assignmentLine(format, *output.EnvName, output.Value)); err != nil {
			return fmt.Errorf("write shell assignment: %w", err)
		}
	}

	return nil
}

// isShellIdentifier reports whether name is safe on the left side of
// a shell assignment. Anything looser could change the meaning of the
// emitted line, so it is skipped instead.
func isShellIdentifier(name string) bool {
	grammar := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	return grammar.MatchString(name)
}

// assignmentLine renders one assignment in the requested dialect.
// Single quotes carry newlines in both dialects, so multiline values
// survive sourcing.
func assignmentLine(format, name, value string) string {
	if format == formatFish {
		return "set -gx " + name + " " + quoteFish(value)
	}

	return "export " + name + "=" + quoteSh(value)
}
