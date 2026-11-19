// Package cmd implements the safetybox command line interface.
//
// Boundary rule: this package translates internal sentinel errors into
// user-facing messages that say what to do. Packages under internal/
// never print. They return errors.
package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/samuel-stidham/safetybox/v4/internal/logging"

	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"
)

const (
	envVault    = "SAFETYBOX_VAULT"
	envIdentity = "SAFETYBOX_IDENTITY"
)

// options holds the global flag values shared by every verb.
type options struct {
	vaultPath      string
	identityPath   string
	passphraseFile string
	jsonCompact    bool
	verbose        bool
	logJSON        bool
}

// Execute runs the root command. It propagates a child process exit
// code from exec and exits 1 on any other error. Fatal exits route
// through [memguard.SafeExit] so any locked key material is wiped
// before the process leaves, even on the error paths.
func Execute(version string) {
	root := newRootCmd(version)

	// Flag-parse failures surface before PersistentPreRun installs the
	// flag-driven logger, so a default-configured one must already be
	// installed for the error record below. A dry-run parse recovers
	// --log-json first: without it, a malformed invocation reported its
	// own error as styled text in a stream the caller asked to keep JSON.
	logging.Setup(root.ErrOrStderr(), logging.Options{JSON: logJSONRequested(version, os.Args[1:])})

	err := root.Execute()
	if err == nil {
		return
	}

	var exit exitCodeError

	if errors.As(err, &exit) {
		// The child already reported its own failure, so propagate only
		// its exit code with no extra safetybox error line. SafeExit
		// terminates the process, so the return is only for clarity.
		memguard.SafeExit(exit.code)

		return
	}

	// SilenceErrors is set on the root, so log the error here rather
	// than let cobra print it, which is what keeps the exit-code path
	// above quiet.
	slog.Error(err.Error())

	memguard.SafeExit(1)
}

func newRootCmd(version string) *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:     "safetybox",
		Short:   "A single-user, versioned secrets vault",
		Long:    "Safetybox is a CLI-first secrets manager. Values are sealed in age envelopes. Metadata lives in SQLite.",
		Version: version,
		PersistentPreRun: func(preRunCmd *cobra.Command, _ []string) {
			logging.Setup(preRunCmd.ErrOrStderr(), logging.Options{Verbose: opts.verbose, JSON: opts.logJSON})
			warnLooseVaultPerms(opts)
		},
		SilenceUsage: true,
		// Execute prints errors itself, so the exec exit-code path can
		// stay quiet instead of adding a redundant safetybox error line
		// on top of the child's own failure output.
		SilenceErrors: true,
	}

	// Help renders through the styled funcs rather than cobra's
	// templates: the default path buffers usage through UsageString,
	// which would hide the real writer from color detection.
	root.SetHelpFunc(styledHelp)
	root.SetUsageFunc(styledUsage)

	flags := root.PersistentFlags()
	flags.StringVar(&opts.vaultPath, "vault", "",
		"path to the vault database (default $XDG_DATA_HOME/safetybox/vault.db)")
	flags.StringVar(&opts.identityPath, "identity", "",
		"path to the identity file (default $XDG_CONFIG_HOME/safetybox/identity.age)")
	flags.StringVar(&opts.passphraseFile, "passphrase-file", "",
		"read the identity passphrase from this file instead of prompting")
	flags.BoolVar(&opts.jsonCompact, "json", false, "emit compact JSON for pipes instead of pretty JSON")
	flags.BoolVarP(&opts.verbose, "verbose", "v", false, "enable debug logging")
	flags.BoolVar(&opts.logJSON, "log-json", false, "emit logs as JSON")

	root.AddCommand(
		newInitCmd(opts),
		newSetCmd(opts),
		newGetCmd(opts),
		newExecCmd(opts),
		newRevealCmd(opts),
		newShowCmd(opts),
		newListCmd(opts),
		newStaleCmd(opts),
		newDisableCmd(opts),
		newDeleteCmd(opts),
		newPurgeCmd(opts),
		newPasswdCmd(opts),
		newRekeyCmd(opts),
		newMigrateCmd(opts),
	)

	return root
}

// logJSONRequested reports whether args ask for JSON logs, read the
// way the real parse will read them. It routes through cobra's own
// Find and a dry-run ParseFlags on a throwaway command tree, so every
// flag arity and exec's non-interspersed rule hold: anything from the
// exec child command onward belongs to the child and never counts.
// The probe must be its own tree. Tolerating unknown flags on the
// real root would make the real parse swallow the very error it
// exists to report.
func logJSONRequested(version string, args []string) bool {
	probe := newRootCmd(version)

	target, flagArgs, err := probe.Find(args)
	if err != nil {
		// A mistyped verb still parses root-level flags, so --log-json
		// is honored on the unknown-command error too.
		target, flagArgs = probe, args
	}

	// An unregistered --help returns pflag.ErrHelp, which the allowlist
	// does not cover, and that stops the dry run before any later
	// --log-json is recorded. So the default help and version flags
	// must exist first, the same way cobra's execute registers them.
	target.InitDefaultHelpFlag()
	target.InitDefaultVersionFlag()

	// The dry run must survive the unknown flag the real parse is
	// about to report. The allowlist goes on the command, not the flag
	// set, because ParseFlags overwrites the flag set's copy.
	target.FParseErrWhitelist = cobra.FParseErrWhitelist{UnknownFlags: true}

	// A dry-run failure is not an error here. Flags apply left to
	// right, so everything parsed before the stop is already recorded.
	// On a stop the allowlist does not cover, such as
	// --log-json=garbage, that is exactly what the real parse will have
	// seen when it fails. On an unknown flag the allowlist carries the
	// probe past the real parse's stop, which is deliberate: the
	// caller's JSON request still counts in `--bogusflag --log-json`.
	_ = target.ParseFlags(flagArgs)

	logJSON := target.Flags().Lookup("log-json")

	return logJSON != nil && logJSON.Value.String() == "true"
}

// resolveVaultPath applies the flag > env > XDG default precedence.
//
// The flag and the environment variable are cleaned here, once, so every
// later use agrees on one spelling. The default is already clean, because
// filepath.Join cleans it. See resolveIdentityPath for what an unclean
// path cost.
func (o *options) resolveVaultPath() (string, error) {
	if o.vaultPath != "" {
		return filepath.Clean(o.vaultPath), nil
	}

	if fromEnv := os.Getenv(envVault); fromEnv != "" {
		return filepath.Clean(fromEnv), nil
	}

	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve vault path: %w", err)
		}

		base = filepath.Join(home, ".local", "share")
	}

	return filepath.Join(base, "safetybox", "vault.db"), nil
}

// resolveIdentityPath applies the flag > env > XDG default precedence.
//
// The flag and the environment variable are cleaned here, once. The Go
// runtime cleans a path before it opens a file, and rename hands the raw
// spelling to the kernel, which resolves "absent/.." literally and fails
// when absent does not exist. A raw path therefore let rekey load the
// identity, commit the vault to the new key, and then fail the identity
// swap, which left the vault unreadable. One clean spelling keeps the
// load, the staging, and the swap on the same file.
func (o *options) resolveIdentityPath() (string, error) {
	if o.identityPath != "" {
		return filepath.Clean(o.identityPath), nil
	}

	if fromEnv := os.Getenv(envIdentity); fromEnv != "" {
		return filepath.Clean(fromEnv), nil
	}

	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve identity path: %w", err)
		}

		base = filepath.Join(home, ".config")
	}

	return filepath.Join(base, "safetybox", "identity.age"), nil
}
