package cmd

import (
	"errors"
	"fmt"
	"os"
	osexec "os/exec"

	"github.com/samuel-stidham/safetybox/internal/secret"
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

	// Rows written before set validated env names can carry names no
	// shell or getenv can address, or that smuggle an `=`. They are
	// skipped with a warning, matching reveal --format. Two secrets
	// can share an env name, and the child would silently keep only
	// the last, so collisions warn too.
	sourceOf := make(map[string]string, len(entries))

	err = forEachDecrypted(cobraCmd, opts, entries, func(entry vault.Entry, _ bool, value secret.Value) error {
		if !isShellIdentifier(entry.EnvName) {
			printStderr(cobraCmd, fmt.Sprintf(
				"warning: secret %s env name %q is not a valid variable name, skipped\n",
				entry.Name, entry.EnvName,
			))

			return nil
		}

		if previous, collided := sourceOf[entry.EnvName]; collided {
			printStderr(cobraCmd, fmt.Sprintf(
				"warning: env name %s from %s overrides the value from %s\n",
				entry.EnvName, entry.Name, previous,
			))
		}

		sourceOf[entry.EnvName] = entry.Name

		env = append(env, entry.EnvName+"="+string(value.Expose()))

		return nil
	})
	if err != nil {
		return nil, err
	}

	return env, nil
}
