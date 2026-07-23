package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/samuel-stidham/safetybox/v2/internal/secret"
	"github.com/samuel-stidham/safetybox/v2/internal/vault"

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
// secret.Value.Expose, the single deliberate display exit. Encoding is
// empty for a plain UTF-8 value and "base64" when Value carries a
// base64 rendering of bytes that JSON cannot hold verbatim.
type revealOutput struct {
	Name      string     `json:"name"`
	EnvName   *string    `json:"envName,omitempty"`
	Version   int64      `json:"version"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Expired   bool       `json:"expired"`
	Encoding  string     `json:"encoding,omitempty"`
	Value     string     `json:"value"`
}

// encodingBase64 marks a reveal value that was base64-encoded because
// its raw bytes are not valid UTF-8.
const encodingBase64 = "base64"

// revealFlags carries the reveal verb's flag values.
type revealFlags struct {
	env    bool
	prefix string
	format string
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
			if err := validateRevealRequest(args, flags, opts.jsonCompact); err != nil {
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
func validateRevealRequest(names []string, flags revealFlags, jsonCompact bool) error {
	usingFilters := flags.env || flags.prefix != ""

	if len(names) > 0 && usingFilters {
		return errors.New("pass names or --env/--prefix filters, not both")
	}

	if len(names) == 0 && !usingFilters {
		return errors.New("pass at least one name, or select a set with --env or --prefix")
	}

	switch flags.format {
	case formatJSON:
		return nil
	case formatSh, formatFish:
		if jsonCompact {
			return errors.New("--json applies to json output, drop it or drop --format")
		}

		return nil
	default:
		return fmt.Errorf("--format %q is not json, sh, or fish", flags.format)
	}
}

func runReveal(cobraCmd *cobra.Command, opts *options, names []string, flags revealFlags) error {
	ctx := cobraCmd.Context()

	entries, recipient, err := collectRevealEntries(ctx, opts, names, flags)
	if err != nil {
		return err
	}

	// A filter that matches nothing never touches the identity, so
	// an empty result costs no passphrase prompt and no KDF.
	outputs := make([]revealOutput, 0)

	if len(entries) > 0 {
		outputs, err = decryptRevealEntries(cobraCmd, opts, recipient, entries)
		if err != nil {
			return err
		}
	}

	if flags.format != formatJSON {
		// Explicitly named secrets fail loudly when unusable, the same
		// contract a missing name gets. Filter selections skip and warn.
		return printShellAssignments(cobraCmd, outputs, flags.format, len(names) > 0)
	}

	encodeNonUTF8(cobraCmd, outputs)

	// A single explicit name keeps the original one-object output
	// shape, so `reveal <name> --json | jq -r .value` stays stable.
	if len(names) == 1 {
		return printJSON(cobraCmd, opts, outputs[0])
	}

	return printJSON(cobraCmd, opts, outputs)
}

// collectRevealEntries selects the secrets to decrypt and returns the
// vault's stored recipient for the decrypt path to verify. Explicit
// names resolve one by one so a missing or deleted name fails loudly.
// Filters select whatever matches, and matching nothing is fine.
func collectRevealEntries(
	ctx context.Context, opts *options, names []string, flags revealFlags,
) ([]vault.Entry, string, error) {
	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return nil, "", err
	}

	defer func() { _ = openedVault.Close() }()

	recipient, err := openedVault.Recipient(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("read stored recipient: %w", err)
	}

	if len(names) > 0 {
		entries, err := entriesByName(ctx, openedVault, names)

		return entries, recipient, err
	}

	entries, err := openedVault.Entries(ctx, vault.EntryFilter{Prefix: flags.prefix, EnvNamed: flags.env})
	if err != nil {
		return nil, "", userHint(err)
	}

	return entries, recipient, nil
}

func entriesByName(ctx context.Context, openedVault *vault.Vault, names []string) ([]vault.Entry, error) {
	entries := make([]vault.Entry, 0, len(names))

	for _, name := range names {
		resolved, err := openedVault.NewestEnabled(ctx, name)
		if err != nil {
			return nil, userHint(err)
		}

		entry := vault.Entry{
			Name:      resolved.Secret.Name,
			Version:   resolved.Version.Number,
			ExpiresAt: resolved.Secret.ExpiresAt,
			Envelope:  resolved.Envelope,
		}

		if resolved.Secret.EnvName != nil {
			entry.EnvName = *resolved.Secret.EnvName
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// decryptRevealEntries opens every envelope through the shared batch
// decrypt path, so a batch pays the passphrase KDF a single time. The
// recipient is verified against the identity before anything decrypts.
func decryptRevealEntries(
	cobraCmd *cobra.Command, opts *options, recipient string, entries []vault.Entry,
) ([]revealOutput, error) {
	outputs := make([]revealOutput, 0, len(entries))

	err := forEachDecrypted(cobraCmd, opts, recipient, entries,
		func(entry vault.Entry, expired bool, value secret.Value) error {
			output := revealOutput{
				Name:      entry.Name,
				Version:   entry.Version,
				ExpiresAt: entry.ExpiresAt,
				Expired:   expired,
				// The one deliberate plaintext display in safetybox.
				Value: string(value.Expose()),
			}

			if entry.EnvName != "" {
				envName := entry.EnvName
				output.EnvName = &envName
			}

			outputs = append(outputs, output)

			return nil
		})
	if err != nil {
		return nil, err
	}

	return outputs, nil
}

// shellUsable explains why an output cannot become an assignment
// line. An empty reason means it can.
func shellUsable(output revealOutput) string {
	switch {
	case output.EnvName == nil:
		return "has no env name"
	case !isShellIdentifier(*output.EnvName):
		return fmt.Sprintf("env name %q is not a shell identifier", *output.EnvName)
	case strings.ContainsRune(output.Value, 0):
		return "value contains a NUL byte, which a shell variable cannot hold"
	default:
		return ""
	}
}

// printShellAssignments writes one assignment line per usable secret.
// With explicit names an unusable secret fails the whole batch before
// anything is emitted, matching how a missing name fails. Filter
// selections skip with a warning on stderr, so a sourced batch never
// silently drops a secret. Duplicate env names warn because the last
// assignment silently wins in the sourcing shell.
func printShellAssignments(cobraCmd *cobra.Command, outputs []revealOutput, format string, explicit bool) error {
	if explicit {
		var unusable []string

		for _, output := range outputs {
			if reason := shellUsable(output); reason != "" {
				unusable = append(unusable, fmt.Sprintf("%s %s", output.Name, reason))
			}
		}

		if len(unusable) > 0 {
			return fmt.Errorf("cannot emit %s assignments: %s (set an env name with `safetybox set <name> --env-name NAME`)",
				format, strings.Join(unusable, "; "))
		}
	}

	sourceOf := make(map[string]string, len(outputs))

	for _, output := range outputs {
		if reason := shellUsable(output); reason != "" {
			printStderr(cobraCmd, fmt.Sprintf("warning: secret %s %s, skipped\n", output.Name, reason))

			continue
		}

		if previous, collided := sourceOf[*output.EnvName]; collided {
			printStderr(cobraCmd, fmt.Sprintf(
				"warning: env name %s from %s overrides the value from %s\n",
				*output.EnvName, output.Name, previous,
			))
		}

		sourceOf[*output.EnvName] = output.Name

		if _, err := fmt.Fprintln(cobraCmd.OutOrStdout(), assignmentLine(format, *output.EnvName, output.Value)); err != nil {
			return fmt.Errorf("write shell assignment: %w", err)
		}
	}

	return nil
}

// encodeNonUTF8 base64-encodes any value JSON cannot carry byte for
// byte. encoding/json would otherwise replace invalid UTF-8 with
// U+FFFD, so a binary value read back from JSON would differ from what
// the vault holds. Encoded values are marked with encoding: "base64"
// and a stderr warning, so a piped consumer can decode them or reach
// for exec instead. It mutates outputs in place.
func encodeNonUTF8(cobraCmd *cobra.Command, outputs []revealOutput) {
	for i := range outputs {
		if utf8.ValidString(outputs[i].Value) {
			continue
		}

		printStderr(cobraCmd, fmt.Sprintf(
			"warning: secret %s is not valid UTF-8, its JSON value is base64-encoded, "+
				"use exec for raw bytes\n",
			outputs[i].Name,
		))

		outputs[i].Value = base64.StdEncoding.EncodeToString([]byte(outputs[i].Value))
		outputs[i].Encoding = encodingBase64
	}
}

// isShellIdentifier reports whether name is safe on the left side of
// a shell assignment: letters, digits, and underscores, not starting
// with a digit. Anything looser could change the meaning of the
// emitted line.
func isShellIdentifier(name string) bool {
	if name == "" || (name[0] >= '0' && name[0] <= '9') {
		return false
	}

	for _, r := range name {
		if !isIdentifierRune(r) {
			return false
		}
	}

	return true
}

func isIdentifierRune(r rune) bool {
	return r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
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
