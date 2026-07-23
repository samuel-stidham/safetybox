package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"syscall"

	"github.com/samuel-stidham/safetybox/v3/internal/secret"
	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"github.com/spf13/cobra"
)

// signalExitBase is the shell convention for a process killed by a
// signal: 128 plus the signal number.
const signalExitBase = 128

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

	// The input is the user's own command line, which is the entire
	// purpose of the exec verb, so it is not tainted. The gosec G204
	// exclusion for this file is recorded in docs/linting.md.
	child := osexec.CommandContext(cobraCmd.Context(), args[0], args[1:]...)

	child.Stdin = cobraCmd.InOrStdin()
	child.Stdout = cobraCmd.OutOrStdout()
	child.Stderr = cobraCmd.ErrOrStderr()
	child.Env = env

	err = child.Run()

	var exit *osexec.ExitError

	if errors.As(err, &exit) {
		return exitCodeError{code: childExitCode(exit)}
	}

	if err != nil {
		return fmt.Errorf("run %s: %w", args[0], err)
	}

	return nil
}

// childExitCode reads the child's exit code the way a shell would. A
// process killed by a signal reports 128 plus the signal number, not
// the -1 that ExitCode returns, so a supervisor keying on 128 plus
// signal reads the death correctly.
func childExitCode(exit *osexec.ExitError) int {
	if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return signalExitBase + int(status.Signal())
	}

	return exit.ExitCode()
}

// envNamedEntries opens the vault, selects every env-named secret, and
// returns them with the vault's stored recipient for the decrypt path
// to verify. The vault is closed before the caller decrypts.
func envNamedEntries(ctx context.Context, opts *options) ([]vault.Entry, string, error) {
	openedVault, err := opts.openVault(ctx)
	if err != nil {
		return nil, "", err
	}

	defer func() { _ = openedVault.Close() }()

	entries, err := openedVault.Entries(ctx, vault.EntryFilter{EnvNamed: true})
	if err != nil {
		return nil, "", userHint(err)
	}

	recipient, err := openedVault.Recipient(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("read stored recipient: %w", err)
	}

	return entries, recipient, nil
}

// buildSecretEnv decrypts every env-named secret into a copy of the
// process environment. Plaintext goes only into the child's
// environment, which is the exec feature itself.
func buildSecretEnv(cobraCmd *cobra.Command, opts *options) ([]string, error) {
	ctx := cobraCmd.Context()

	entries, recipient, err := envNamedEntries(ctx, opts)
	if err != nil {
		return nil, err
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

	// exec always selects a batch by env-name filter, never a single
	// explicit name, so a mismatching secret is skipped with a warning
	// rather than aborting the run and denying every variable to the child.
	err = forEachDecrypted(cobraCmd, opts, recipient, entries, false,
		func(entry vault.Entry, _ bool, value secret.Value) error {
			if !isShellIdentifier(entry.EnvName) {
				printStderr(cobraCmd, fmt.Sprintf(
					"warning: secret %s env name %q is not a valid variable name, skipped\n",
					entry.Name, entry.EnvName,
				))

				return nil
			}

			// A NUL byte in the value makes os/exec reject the whole
			// environment, which would fail every command exec runs. Skip
			// the offending secret with a warning that names it, the way
			// reveal --format handles the same value, rather than letting
			// one binary secret deny the verb.
			if bytes.IndexByte(value.Expose(), 0) >= 0 {
				printStderr(cobraCmd, fmt.Sprintf(
					"warning: secret %s value contains a NUL byte, which an environment variable cannot hold, skipped\n",
					entry.Name,
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
