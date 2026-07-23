package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/samuel-stidham/safetybox/v2/internal/envelope"
	"github.com/samuel-stidham/safetybox/v2/internal/secret"
	"github.com/samuel-stidham/safetybox/v2/internal/vault"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type setOutput struct {
	Name      string      `json:"name"`
	Version   int64       `json:"version"`
	State     vault.State `json:"state"`
	EnvName   *string     `json:"envName,omitempty"`
	ExpiresAt *time.Time  `json:"expiresAt,omitempty"`
	Revoked   int64       `json:"revokedPrevious"`
}

// setFlags carries the set verb's flag values.
type setFlags struct {
	envName        string
	expires        string
	revokePrevious bool
}

func newSetCmd(opts *options) *cobra.Command {
	var flags setFlags

	setCmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Store a new version of a secret",
		Long: "set reads the value from stdin, or from a no-echo prompt on a " +
			"terminal, and appends it as a new enabled version. Values never " +
			"come from arguments. Prior versions stay enabled unless " +
			"--revoke-previous is passed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runSet(cobraCmd, opts, args[0], flags)
		},
	}

	setCmd.Flags().StringVar(&flags.envName, "env-name", "", "environment variable name used by exec")
	setCmd.Flags().StringVar(&flags.expires, "expires", "",
		"expiry as RFC3339 or YYYY-MM-DD (staleness flag, never deletion)")
	setCmd.Flags().BoolVar(&flags.revokePrevious, "revoke-previous", false, "disable all older enabled versions")

	return setCmd
}

func runSet(cobraCmd *cobra.Command, opts *options, name string, flags setFlags) error {
	setOpts, err := setOptionsFromFlags(cobraCmd, flags)
	if err != nil {
		return err
	}

	value, err := readSecretValue(cobraCmd, name)
	if err != nil {
		return err
	}

	defer zeroBytes(value)

	ctx := cobraCmd.Context()

	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return err
	}

	defer func() { _ = openedVault.Close() }()

	recipient, err := storedRecipient(ctx, openedVault)
	if err != nil {
		return err
	}

	result, err := openedVault.AppendVersion(ctx, name, setOpts, func(address string) ([]byte, error) {
		plaintext := secret.New(value)
		defer plaintext.Destroy()

		return envelope.Seal(recipient, address, plaintext)
	})
	if err != nil {
		return userHint(err)
	}

	return printJSON(cobraCmd, opts, setOutput{
		Name:      result.Secret.Name,
		Version:   result.Version.Number,
		State:     result.Version.State,
		EnvName:   result.Secret.EnvName,
		ExpiresAt: result.Secret.ExpiresAt,
		Revoked:   result.Revoked,
	})
}

// setOptionsFromFlags translates the set flags into vault options. An
// empty --env-name clears the env name, and an empty --expires clears
// the expiry, both distinguished from "unset" by Flags().Changed.
func setOptionsFromFlags(cobraCmd *cobra.Command, flags setFlags) (vault.SetOptions, error) {
	setOpts := vault.SetOptions{RevokePrevious: flags.revokePrevious}

	if cobraCmd.Flags().Changed("env-name") {
		// A non-empty env name must be a valid shell identifier so that
		// exec and reveal --format can emit it as a variable name. An
		// empty value is the signal to clear the env name.
		if flags.envName != "" && !isShellIdentifier(flags.envName) {
			return vault.SetOptions{}, fmt.Errorf("--env-name %q is not a valid shell identifier", flags.envName)
		}

		setOpts.EnvName = &flags.envName
	}

	if cobraCmd.Flags().Changed("expires") {
		// An explicit empty value clears the expiry, mirroring how an
		// empty --env-name clears the env name. Without this an expiry
		// could never be removed, and `--expires ""` was silently a
		// no-op that reported success.
		if flags.expires == "" {
			setOpts.ClearExpiry = true

			return setOpts, nil
		}

		expiresAt, err := parseExpiry(flags.expires)
		if err != nil {
			return vault.SetOptions{}, err
		}

		setOpts.ExpiresAt = &expiresAt
	}

	return setOpts, nil
}

// readSecretValue reads the plaintext from a no-echo prompt on a
// terminal, or from stdin otherwise. Values never come from argv.
func readSecretValue(cobraCmd *cobra.Command, name string) ([]byte, error) {
	stdinFd := int(os.Stdin.Fd())

	if term.IsTerminal(stdinFd) {
		return promptOnce(cobraCmd, fmt.Sprintf("Value for %s: ", name), "value")
	}

	content, err := secret.ReadAllWiping(cobraCmd.InOrStdin())
	if err != nil {
		return nil, fmt.Errorf("read value from stdin: %w", err)
	}

	// Strip one trailing newline so `echo value | safetybox set`
	// stores what was typed. Deeper newlines are preserved.
	value := bytes.TrimSuffix(content, []byte("\n"))
	value = bytes.TrimSuffix(value, []byte("\r"))

	if len(value) == 0 {
		return nil, errors.New("value must not be empty")
	}

	return value, nil
}

// parseExpiry accepts RFC3339 or a bare date, which means midnight
// UTC of that day.
func parseExpiry(raw string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC(), nil
	}

	parsed, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse --expires %q: use RFC3339 or YYYY-MM-DD: %w", raw, err)
	}

	return parsed.UTC(), nil
}
