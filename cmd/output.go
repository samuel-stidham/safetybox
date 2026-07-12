package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// nowUTC is the single clock read used for expiry decisions.
func nowUTC() time.Time {
	return time.Now().UTC()
}

// printJSON renders payload as pretty JSON, or compact JSON when
// --json is set. Redaction is enforced by secret.Value, never by
// omitting fields here.
func printJSON(cobraCmd *cobra.Command, opts *options, payload any) error {
	var (
		encoded []byte
		err     error
	)

	if opts.jsonCompact {
		encoded, err = json.Marshal(payload)
	} else {
		encoded, err = json.MarshalIndent(payload, "", "  ")
	}

	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}

	_, _ = fmt.Fprintln(cobraCmd.OutOrStdout(), string(encoded))

	return nil
}

// warnExpired tells the user on stderr that a secret is stale.
// Expired secrets still resolve. Expiry is never a deletion trigger.
func warnExpired(cobraCmd *cobra.Command, name string, expiresAt *time.Time) {
	if expiresAt == nil {
		return
	}

	printStderr(cobraCmd, fmt.Sprintf("warning: secret %s expired at %s\n",
		name, expiresAt.UTC().Format(time.RFC3339)))
}
