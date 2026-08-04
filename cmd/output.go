package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
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

	// A discarded write error here would let a full disk or a broken
	// pipe exit 0 with truncated output, which a consuming script reads
	// as success. reveal's shell-assignment path already checks its
	// writes, so this keeps the JSON path consistent with it.
	if _, err := fmt.Fprintln(cobraCmd.OutOrStdout(), string(encoded)); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}

// warnExpired records that a secret is stale. Expired secrets still
// resolve. Expiry is never a deletion trigger.
func warnExpired(name string, expiresAt *time.Time) {
	if expiresAt == nil {
		return
	}

	slog.Warn("secret expired", "name", name, "expires_at", expiresAt.UTC().Format(time.RFC3339))
}
