package cmd

import (
	"errors"
	"fmt"
	"os"
	osexec "os/exec"

	"github.com/samuel-stidham/safetybox/internal/envelope"
	"github.com/samuel-stidham/safetybox/internal/vault"

	"github.com/spf13/cobra"
)

func newExecCmd(opts *options) *cobra.Command {
	return &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run a command with secrets injected into its environment",
		Long: "exec resolves every secret that has an env name, decrypts its " +
			"newest enabled version, and runs the command with those " +
			"variables added to the environment. The child's exit code is " +
			"propagated.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runExec(cobraCmd, opts, args)
		},
	}
}

func runExec(cobraCmd *cobra.Command, opts *options, args []string) error {
	env, err := buildSecretEnv(cobraCmd, opts)
	if err != nil {
		return err
	}

	// G204 guards against untrusted input reaching a subprocess. Here
	// the "input" is the user's own command line, which is the entire
	// purpose of the exec verb. No sanitization could keep the verb
	// useful, so this is a documented false positive.
	child := osexec.CommandContext(cobraCmd.Context(), args[0], args[1:]...) //nolint:gosec

	child.Stdin = cobraCmd.InOrStdin()
	child.Stdout = cobraCmd.OutOrStdout()
	child.Stderr = cobraCmd.ErrOrStderr()
	child.Env = env

	err = child.Run()

	var exit *osexec.ExitError

	if errors.As(err, &exit) {
		return exitCodeError{code: exit.ExitCode()}
	}

	if err != nil {
		return fmt.Errorf("run %s: %w", args[0], err)
	}

	return nil
}

// buildSecretEnv decrypts every env-named secret into a copy of the
// process environment. Plaintext goes only into the child's
// environment, which is the exec feature itself.
func buildSecretEnv(cobraCmd *cobra.Command, opts *options) ([]string, error) {
	openedVault, err := opts.openVault()
	if err != nil {
		return nil, err
	}

	entries, err := openedVault.Entries(vault.EntryFilter{EnvNamed: true})

	_ = openedVault.Close()

	if err != nil {
		return nil, userHint(err)
	}

	env := os.Environ()

	if len(entries) == 0 {
		return env, nil
	}

	key, cleanup, err := loadIdentity(cobraCmd, opts)
	if err != nil {
		return nil, err
	}

	defer cleanup()

	now := nowUTC()

	for _, entry := range entries {
		address := vault.CanonicalAddress(entry.Name, entry.Version)

		value, err := envelope.Open(key, address, entry.Envelope)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", entry.Name, userHint(err))
		}

		if entry.ExpiresAt != nil && !now.Before(*entry.ExpiresAt) {
			warnExpired(cobraCmd, entry.Name, entry.ExpiresAt)
		}

		env = append(env, entry.EnvName+"="+string(value.Expose()))
	}

	return env, nil
}
