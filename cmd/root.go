// Package cmd implements the safetybox command line interface.
//
// Boundary rule: this package translates internal sentinel errors into
// user-facing messages that say what to do. Packages under internal/
// never print. They return errors.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/samuel-stidham/safetybox/internal/logging"

	"github.com/awnumar/memguard"
	"github.com/spf13/cobra"
)

const (
	envVault    = "SAFETYBOX_VAULT"
	envIdentity = "SAFETYBOX_IDENTITY"
)

// logo is the banner shown at the top of the root help and version
// output. It spells SAFETYBOX in block glyphs.
const logo = ` ▗▄▄▖ ▗▄▖ ▗▄▄▄▖▗▄▄▄▖▗▄▄▄▖▗▖  ▗▖▗▄▄▖  ▗▄▖ ▗▖  ▗▖
▐▌   ▐▌ ▐▌▐▌   ▐▌     █   ▝▚▞▘ ▐▌ ▐▌▐▌ ▐▌ ▝▚▞▘
 ▝▀▚▖▐▛▀▜▌▐▛▀▀▘▐▛▀▀▘  █    ▐▌  ▐▛▀▚▖▐▌ ▐▌  ▐▌
▗▄▄▞▘▐▌ ▐▌▐▌   ▐▙▄▄▖  █    ▐▌  ▐▙▄▞▘▝▚▄▞▘▗▞▘▝▚▖`

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

	// SilenceErrors is set on the root, so print the error here rather
	// than let cobra print it, which is what keeps the exit-code path
	// above quiet.
	_, _ = fmt.Fprintln(root.ErrOrStderr(), "Error:", err)

	memguard.SafeExit(1)
}

func newRootCmd(version string) *cobra.Command {
	opts := &options{}

	root := &cobra.Command{
		Use:   "safetybox",
		Short: "A single-user, versioned secrets vault",
		Long: logo + "\n\nsafetybox " + version + "\n\n" +
			"safetybox is a CLI-first secrets manager. Values are sealed in age envelopes. Metadata lives in SQLite.",
		Version: version,
		PersistentPreRun: func(preRunCmd *cobra.Command, _ []string) {
			logging.Setup(logging.Options{Verbose: opts.verbose, JSON: opts.logJSON})
			warnLooseVaultPerms(preRunCmd, opts)
		},
		SilenceUsage: true,
		// Execute prints errors itself, so the exec exit-code path can
		// stay quiet instead of adding a redundant safetybox error line
		// on top of the child's own failure output.
		SilenceErrors: true,
	}

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
	)

	return root
}

// resolveVaultPath applies the flag > env > XDG default precedence.
func (o *options) resolveVaultPath() (string, error) {
	if o.vaultPath != "" {
		return o.vaultPath, nil
	}

	if fromEnv := os.Getenv(envVault); fromEnv != "" {
		return fromEnv, nil
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
func (o *options) resolveIdentityPath() (string, error) {
	if o.identityPath != "" {
		return o.identityPath, nil
	}

	if fromEnv := os.Getenv(envIdentity); fromEnv != "" {
		return fromEnv, nil
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
