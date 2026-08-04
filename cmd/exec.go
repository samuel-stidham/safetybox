package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"strings"
	"syscall"

	"github.com/samuel-stidham/safetybox/v4/internal/secret"
	"github.com/samuel-stidham/safetybox/v4/internal/vault"

	"github.com/spf13/cobra"
)

// signalExitBase is the shell convention for a process killed by a
// signal: 128 plus the signal number.
const signalExitBase = 128

func newExecCmd(opts *options) *cobra.Command {
	execCmd := &cobra.Command{
		Use:   "exec -- <command> [args...]",
		Short: "Run a command with secrets injected into its environment",
		Long: "exec resolves every secret that has an env name, decrypts its " +
			"newest enabled version, and runs the command with those " +
			"variables added to the environment. The child's exit code is " +
			"propagated.\n\n" +
			"safetybox's own flags must come before the command. Everything " +
			"from the command name onward belongs to the child, so a child " +
			"flag never changes which vault or identity safetybox reads.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cobraCmd *cobra.Command, args []string) error {
			return runExec(cobraCmd, opts, args)
		},
	}

	// Stop parsing flags at the command name. Interspersed parsing let a
	// flag after the child command bind to safetybox instead, so
	// "safetybox exec sh -c ... --vault EVIL" redirected the vault, the
	// identity, and the passphrase file, and the child silently lost
	// those arguments. A wrapper shaped like `safetybox exec cmd "$@"`
	// handed that control to whoever supplied "$@".
	execCmd.Flags().SetInterspersed(false)

	return execCmd
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

	var notInjectable int

	// exec always selects a batch by env-name filter, never a single
	// explicit name, so a mismatching secret is skipped with a warning
	// rather than aborting the run and denying every variable to the child.
	skipped, err := forEachDecrypted(cobraCmd, opts, recipient, entries, false,
		func(entry vault.Entry, _ bool, value secret.Value) error {
			if reason := envInjectable(entry, value); reason != "" {
				slog.Warn("secret skipped", "name", entry.Name, "reason", reason)

				notInjectable++

				return nil
			}

			if previous, collided := sourceOf[entry.EnvName]; collided {
				slog.Warn("env name collision, the later secret overrides the earlier value",
					"env_name", entry.EnvName, "name", entry.Name, "previous", previous)
			}

			sourceOf[entry.EnvName] = entry.Name

			env = append(env, entry.EnvName+"="+string(value.Expose()))

			return nil
		})
	if err != nil {
		return nil, err
	}

	kept := withoutSkipped(env, skipped, sourceOf)

	// sourceOf holds one entry per delivered variable, so its length is
	// what the child actually sees: a collision collapses to one.
	// not_injected counts every decrypted entry withheld from the child,
	// the not-injectable ones plus the metadata-mismatch skips. The name
	// is distinct on purpose: forEachDecrypted's "skipped" key counts
	// only the mismatch skips.
	slog.Debug("child environment built", "injected", len(sourceOf), "not_injected", notInjectable+len(skipped))

	return kept, nil
}

// envInjectable explains why an entry cannot become a child environment
// variable. An empty reason means it can. It mirrors reveal's
// shellUsable, so the two batch verbs refuse the same things for the
// same stated reasons.
func envInjectable(entry vault.Entry, value secret.Value) string {
	switch {
	case !isShellIdentifier(entry.EnvName):
		return fmt.Sprintf("env name %q is not a valid variable name", entry.EnvName)
	case isReservedEnvName(entry.EnvName):
		// set refuses these names, but a row can predate that check or be
		// forged: sealing an envelope needs only the recipient, which the
		// vault stores in the clear. Skipping leaves the child with the real
		// PATH it inherited instead of one the vault supplied.
		return fmt.Sprintf("env name %q is reserved, so a secret must not supply it", entry.EnvName)
	case bytes.IndexByte(value.Expose(), 0) >= 0:
		// A NUL byte in the value makes os/exec reject the whole
		// environment, which would fail every command exec runs. Skipping
		// the one secret keeps a binary value from denying the verb.
		return "value contains a NUL byte, which an environment variable cannot hold"
	default:
		return ""
	}
}

// withoutSkipped removes every variable a skipped secret was supposed to
// supply, so the child cannot read a stale value under that name.
//
// Skipping used to be described as fail-safe, and on its own it is not.
// buildSecretEnv starts from os.Environ, so a variable the parent already
// held stayed visible to the child after safetybox declined to deliver
// the real secret. The child could not tell the difference, and the run
// still exited 0. Absent is a state the child can detect. Stale is not.
//
// A skipped secret whose env name another secret legitimately supplied is
// left alone, since that name is not stale.
func withoutSkipped(env []string, skipped []vault.Entry, delivered map[string]string) []string {
	toClear := staleEnvNames(skipped, delivered)
	if len(toClear) == 0 {
		return env
	}

	kept := make([]string, 0, len(env))

	for _, assignment := range env {
		name, _, _ := strings.Cut(assignment, "=")

		if _, drop := toClear[name]; drop {
			continue
		}

		kept = append(kept, assignment)
	}

	for name := range toClear {
		slog.Warn("variable cleared from the environment, so the child cannot read a stale value", "env_name", name)
	}

	return kept
}

// staleEnvNames collects the variable names a skipped secret was meant to
// supply and nothing else did. A name another secret legitimately
// supplied is current rather than stale, so it stays.
func staleEnvNames(skipped []vault.Entry, delivered map[string]string) map[string]struct{} {
	stale := make(map[string]struct{}, len(skipped))

	for _, entry := range skipped {
		if entry.EnvName == "" || !isShellIdentifier(entry.EnvName) {
			continue
		}

		if _, supplied := delivered[entry.EnvName]; supplied {
			continue
		}

		stale[entry.EnvName] = struct{}{}
	}

	return stale
}
