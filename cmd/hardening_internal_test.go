package cmd

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samuel-stidham/safetybox/v3/internal/envelope"
	"github.com/samuel-stidham/safetybox/v3/internal/identity"
	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

// failingWriter fails every write, standing in for a full disk or a
// broken pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("simulated write failure")
}

// TestPrintJSONReturnsWriteError covers B-2: a failed stdout write must
// surface as an error, not a silent exit 0 with truncated output.
func TestPrintJSONReturnsWriteError(t *testing.T) {
	command := &cobra.Command{}
	command.SetOut(failingWriter{})

	err := printJSON(command, &options{}, map[string]string{"name": "fake"})

	require.Error(t, err)
	assert.ErrorContains(t, err, "write output")
}

// TestPrintJSONSucceedsToBuffer pins the normal path still returns nil.
func TestPrintJSONSucceedsToBuffer(t *testing.T) {
	command := &cobra.Command{}

	var out bytes.Buffer

	command.SetOut(&out)

	require.NoError(t, printJSON(command, &options{}, map[string]string{"name": "fake"}))
	assert.Contains(t, out.String(), "fake")
}

// TestExecSkipsNulValuedSecret covers B-1: one env-named secret with a
// NUL byte must not break exec for every command. It is skipped with a
// warning that names it, and the other secrets still inject.
func TestExecSkipsNulValuedSecret(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("abc\x00def\n", "set", "lab/nul", "--env-name", "FAKE_NUL")
	fixture.runOK(fakeValueOne+"\n", "set", "lab/ok", "--env-name", "FAKE_OK")

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_OK"`)

	assert.Equal(t, fakeValueOne, stdout, "the usable secret must still inject")
	assert.Contains(t, stderr, "lab/nul", "the skipped secret must be named")
	assert.Contains(t, stderr, "NUL")
}

// TestExecExitCodeStaysQuietOnStderr covers B-7: a propagated child
// exit code must not carry an extra safetybox error line.
func TestExecExitCodeStaysQuietOnStderr(t *testing.T) {
	fixture := newCLIFixture(t)

	_, stderr, err := fixture.run("", "exec", "--", "sh", "-c", "exit 3")

	var exit exitCodeError

	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 3, exit.code)
	assert.NotContains(t, stderr, "command exited with code")
	assert.NotContains(t, stderr, "Error:")
}

// TestLooseVaultPermsWarnOnOpen covers A-1 and B-5: a loosened vault
// file warns on stderr, unlike the identity file which refuses.
func TestLooseVaultPermsWarnOnOpen(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	require.NoError(t, os.Chmod(fixture.vaultPath, 0o644))

	_, stderr := fixture.runOK("", "list")

	assert.Contains(t, stderr, "group or world can access")
	assert.Contains(t, stderr, "0644")
}

// TestHalfCreatedVaultHints covers B-4: a schema-less file at the vault
// path must fail with a recovery hint, not a raw driver error.
func TestHalfCreatedVaultHints(t *testing.T) {
	tmp := t.TempDir()
	vaultPath := filepath.Join(tmp, "vault.db")

	require.NoError(t, os.WriteFile(vaultPath, nil, 0o600))

	root := newRootCmd("test")
	root.SetArgs([]string{"--vault", vaultPath, "list"})

	var stdout, stderr bytes.Buffer

	root.SetOut(&stdout)
	root.SetErr(&stderr)

	err := root.Execute()

	require.Error(t, err)
	assert.ErrorContains(t, err, "half-created")
}

// swapVaultRecipient rewrites the vault's stored recipient directly,
// standing in for a vault-write attacker.
func swapVaultRecipient(t *testing.T, vaultPath, recipient string) {
	t.Helper()

	handle, err := sql.Open("sqlite", "file:"+vaultPath)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	_, err = handle.ExecContext(t.Context(),
		"UPDATE vault_meta SET value = ? WHERE key = 'recipient'", recipient)
	require.NoError(t, err)
}

// setFormatVersion rewrites the vault's stored format version directly,
// standing in for a vault written by a different safetybox build.
func setFormatVersion(t *testing.T, vaultPath, version string) {
	t.Helper()

	handle, err := sql.Open("sqlite", "file:"+vaultPath)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	_, err = handle.ExecContext(t.Context(),
		"UPDATE vault_meta SET value = ? WHERE key = 'format_version'", version)
	require.NoError(t, err)
}

// TestMigrateOnNewerFormatDoesNotSuggestMigrate covers I5. A vault in a
// format newer than this build cannot be upgraded by it, so the error
// must point at upgrading the binary, not circularly at running migrate.
func TestMigrateOnNewerFormatDoesNotSuggestMigrate(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	setFormatVersion(t, fixture.vaultPath, "9")

	_, _, err := fixture.run("", "migrate")
	require.ErrorContains(t, err, "upgrade safetybox")
	assert.NotContains(t, err.Error(), "run `safetybox migrate`",
		"the migrate error must not tell the user to run migrate")
}

// TestReadRefusesSwappedRecipient covers A-4: after the stored recipient
// is swapped, every read verb must refuse with a clear tamper error,
// not decrypt or fail vaguely.
func TestReadRefusesSwappedRecipient(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_ONE")

	attacker, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	swapVaultRecipient(t, fixture.vaultPath, attacker.Recipient().String())

	_, _, err = fixture.run("", "get", "api/one")
	require.ErrorIs(t, err, ErrRecipientMismatch)

	_, _, err = fixture.run("", "reveal", "api/one")
	require.ErrorIs(t, err, ErrRecipientMismatch)

	_, _, err = fixture.run("", "exec", "--", "true")
	require.ErrorIs(t, err, ErrRecipientMismatch)
}

// tamperColumn edits a plaintext secret column directly, standing in for
// a vault-write attacker who does not re-seal the value. The query per
// column is a fixed literal, so no value is concatenated into the SQL.
func tamperColumn(t *testing.T, vaultPath, column, value, name string) {
	t.Helper()

	var query string

	switch column {
	case "env_name":
		query = "UPDATE secret SET env_name = ? WHERE name = ?"
	case "expires_at":
		query = "UPDATE secret SET expires_at = ? WHERE name = ?"
	default:
		t.Fatalf("unsupported column %q", column)
	}

	handle, err := sql.Open("sqlite", "file:"+vaultPath)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	_, err = handle.ExecContext(t.Context(), query, value, name)
	require.NoError(t, err)
}

// TestReadRefusesTamperedEnvName covers the v3 metadata binding: an
// attacker who edits the env name column without re-sealing the value
// is caught on the next read, because the sealed env name no longer
// matches the column. An explicitly named read fails loud. A batch verb
// skips the mismatching secret with a warning and runs on.
func TestReadRefusesTamperedEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_ONE")

	tamperColumn(t, fixture.vaultPath, "env_name", "FAKE_EVIL", "api/one")

	_, _, err := fixture.run("", "get", "api/one")
	require.ErrorIs(t, err, ErrMetadataTampered)

	_, _, err = fixture.run("", "reveal", "api/one")
	require.ErrorIs(t, err, ErrMetadataTampered)

	// exec is a batch verb. The tampered secret is skipped with a warning
	// that names it, and the child still runs, rather than one bad secret
	// denying every variable to every command exec runs.
	_, stderr, err := fixture.run("", "exec", "--", "true")
	require.NoError(t, err, "a batch verb skips the tampered secret and runs the child")
	assert.Contains(t, stderr, "api/one")
	assert.Contains(t, stderr, "does not match the sealed value")
}

// TestReadRefusesTamperedExpiry covers the same binding for the expiry
// column: adding or changing an expiry the sealed value does not carry
// is caught on read.
func TestReadRefusesTamperedExpiry(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/exp")

	tamperColumn(t, fixture.vaultPath, "expires_at", "2099-01-01T00:00:00Z", "api/exp")

	_, _, err := fixture.run("", "get", "api/exp")
	require.ErrorIs(t, err, ErrMetadataTampered)
}

// TestReadRefusesEmptyEnvName covers L1. The store maps an empty env
// name to NULL and never writes a present empty string, so a
// valid-but-empty env_name column is a tampered state the frame cannot
// represent. Flipping NULL to empty also pulls the secret into the
// env_name IS NOT NULL filter, so an explicit read must refuse and the
// batch --env selection must skip it rather than print its value.
func TestReadRefusesEmptyEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	// A secret with no env name, so the --env filter excludes it.
	fixture.runOK(fakeValueOne+"\n", "set", "api/noenv")

	// Flip the column from NULL to empty string, standing in for a
	// vault-write attacker.
	tamperColumn(t, fixture.vaultPath, "env_name", "", "api/noenv")

	// An explicit read refuses, catching the metadata edit.
	_, _, err := fixture.run("", "get", "api/noenv")
	require.ErrorIs(t, err, ErrMetadataTampered)

	// The flip newly selects the secret for reveal --env, but the batch
	// path skips it with a warning rather than printing its value.
	stdout, stderr := fixture.runOK("", "reveal", "--env")
	assert.NotContains(t, stdout, fakeValueOne, "the flipped secret's value must not be printed")
	assert.Contains(t, stderr, "api/noenv", "the skipped secret must be named")
}

// TestDisabledNewestVersionFailsSafeAfterMetadataChange covers M2 and the
// documented fail-safe edge that had no test. Changing a secret's env
// name writes a new version, and disabling that version leaves the older
// enabled version bound to the old metadata while the column holds the
// new value. An explicit read refuses, so the operator learns the secret
// is unreadable. A batch verb skips it with a warning and still delivers
// the healthy secrets, so one stale secret does not deny the whole run.
// Re-setting the secret reconciles the state.
func TestDisabledNewestVersionFailsSafeAfterMetadataChange(t *testing.T) {
	fixture := newCLIFixture(t)

	// A healthy env-named secret shares the exec batch with the stale one.
	fixture.runOK(fakeValueTwo+"\n", "set", "api/healthy", "--env-name", "FAKE_HEALTHY")

	// Version 1 has no env name, version 2 adds one, then version 2 is
	// disabled, so the newest enabled version is 1 with stale metadata.
	fixture.runOK(fakeValueOne+"\n", "set", "api/foo")
	fixture.runOK(fakeValueOne+"\n", "set", "api/foo", "--env-name", "FAKE_FOO")
	fixture.runOK("", "disable", "api/foo", "2")

	// An explicit read fails loud on both get and reveal.
	_, _, err := fixture.run("", "get", "api/foo")
	require.ErrorIs(t, err, ErrMetadataTampered)

	_, _, err = fixture.run("", "reveal", "api/foo")
	require.ErrorIs(t, err, ErrMetadataTampered)

	// exec skips the stale secret with a warning and still injects the
	// healthy one, so one stale secret does not deny the whole batch.
	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_HEALTHY"`)
	assert.Equal(t, fakeValueTwo, stdout, "the healthy secret must still inject")
	assert.Contains(t, stderr, "api/foo", "the skipped stale secret must be named")

	// Re-setting the secret re-seals the newest version with the current
	// column, so reads reconcile and succeed again.
	fixture.runOK(fakeValueThree+"\n", "set", "api/foo", "--env-name", "FAKE_FOO")
	assert.Equal(t, fakeValueThree, fixture.revealValue("api/foo"))
}

// downgradeToV1 rewrites a fixture's vault to format 1 with legacy
// address-only envelopes, standing in for a vault from an older
// safetybox. It decrypts each current envelope and re-seals it in the
// v1 frame, then sets the format version back to 1.
func downgradeToV1(t *testing.T, fixture *cliFixture) {
	t.Helper()

	passphrase, err := os.ReadFile(fixture.passphraseFile)
	require.NoError(t, err)

	key, cleanup, err := identity.Load(fixture.identityPath, bytes.TrimRight(passphrase, "\n"))
	require.NoError(t, err)

	defer cleanup()

	handle, err := sql.Open("sqlite", "file:"+fixture.vaultPath)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	for _, row := range readVersionRows(t, handle) {
		address := vault.CanonicalAddress(row.name, row.number)

		value, _, err := envelope.Open(key, address, row.blob)
		require.NoError(t, err)

		legacy := sealLegacyForTest(t, key.Recipient(), address, value.Expose())
		value.Destroy()

		_, err = handle.ExecContext(t.Context(),
			"UPDATE secret_version SET envelope = ? WHERE id = ?", legacy, row.id)
		require.NoError(t, err)
	}

	_, err = handle.ExecContext(t.Context(),
		"UPDATE vault_meta SET value = '1' WHERE key = 'format_version'")
	require.NoError(t, err)
}

// versionRow is one secret_version row with its envelope, for the
// downgrade helper.
type versionRow struct {
	id     int64
	name   string
	number int64
	blob   []byte
}

// readVersionRows returns every version that still has an envelope. It
// drains the cursor before returning, so the deferred close satisfies
// the single-connection rule and the linter.
func readVersionRows(t *testing.T, handle *sql.DB) []versionRow {
	t.Helper()

	rows, err := handle.QueryContext(t.Context(),
		`SELECT sv.id, s.name, sv.version_number, sv.envelope
		 FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
		 WHERE sv.envelope IS NOT NULL`)
	require.NoError(t, err)

	defer func() { _ = rows.Close() }()

	var versions []versionRow

	for rows.Next() {
		var row versionRow

		require.NoError(t, rows.Scan(&row.id, &row.name, &row.number, &row.blob))
		versions = append(versions, row)
	}

	require.NoError(t, rows.Err())

	return versions
}

// sealLegacyForTest builds a version 1 envelope: the address, a newline,
// then the value, encrypted to the recipient.
func sealLegacyForTest(t *testing.T, recipient age.Recipient, address string, value []byte) []byte {
	t.Helper()

	var raw bytes.Buffer

	writer, err := age.Encrypt(&raw, recipient)
	require.NoError(t, err)

	_, err = writer.Write([]byte(address + "\n"))
	require.NoError(t, err)

	_, err = writer.Write(value)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	return raw.Bytes()
}

// TestMigrateUpgradesOldVault covers the v3 format migration end to end.
// A format 1 vault with legacy envelopes is refused, migrate re-seals
// every envelope into the v2 frame, and afterward reads work and the
// metadata tamper check is in force.
func TestMigrateUpgradesOldVault(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_ONE")

	downgradeToV1(t, fixture)

	// The format 1 vault is refused until it is migrated.
	_, _, err := fixture.run("", "get", "api/one")
	require.ErrorIs(t, err, vault.ErrFormatVersion)

	stdout, _ := fixture.runOK("", "migrate")
	assert.InDelta(t, 1, decode(t, stdout)["migratedVersions"], 0, "one version must migrate")

	// Reads work again and return the original value.
	assert.Equal(t, fakeValueOne, fixture.revealValue("api/one"))

	// The tamper check now guards the migrated vault.
	tamperColumn(t, fixture.vaultPath, "env_name", "FAKE_EVIL", "api/one")

	_, _, err = fixture.run("", "get", "api/one")
	require.ErrorIs(t, err, ErrMetadataTampered)
}

// TestMigrateReadsPassphraseFromFifo pins that migrate accepts a
// passphrase from a process substitution, such as
// `--passphrase-file (secret-get name | psub)`, not only a regular
// file. migrate reads the passphrase before it checks the format, so
// running it on a current vault proves the fifo was read by reaching
// the already-current message.
func TestMigrateReadsPassphraseFromFifo(t *testing.T) {
	fixture := newCLIFixture(t)

	fifo := filepath.Join(t.TempDir(), "pass.fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))

	go func() {
		writer, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			return
		}

		_, _ = writer.WriteString(fakePassphrase + "\n")
		_ = writer.Close()
	}()

	fixture.passphraseFile = fifo

	_, stderr := fixture.runOK("", "migrate")
	assert.Contains(t, stderr, "already at the current format",
		"migrate must read the passphrase from the fifo and reach the format check")
}

// TestMigrateStripsNewlineEnvName covers M3. A vault written before set
// validated env names can hold one with a newline, which the version 2
// frame cannot store. Without handling, migrate would roll back and the
// vault could never open in v3. migrate strips the newline, warns naming
// the secret, reconciles the column, and completes, so the value reads
// back and the stored env name no longer carries the newline.
func TestMigrateStripsNewlineEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/legacy", "--env-name", "FAKE_LEGACY")

	// Inject a newline into the env name column directly, standing in for
	// a pre-validation vault, then downgrade to the legacy frame so
	// migrate has real work to do.
	tamperColumn(t, fixture.vaultPath, "env_name", "FAKE\nLEGACY", "api/legacy")
	downgradeToV1(t, fixture)

	stdout, stderr := fixture.runOK("", "migrate")
	assert.InDelta(t, 1, decode(t, stdout)["migratedVersions"], 0, "the one version must migrate")
	assert.Contains(t, stderr, "api/legacy", "the sanitized secret must be named")
	assert.Contains(t, stderr, "newline", "the warning must explain what changed")

	// The value reads back, proving migration completed rather than
	// rolling back.
	assert.Equal(t, fakeValueOne, fixture.revealValue("api/legacy"))

	// The stored env name lost its newline, so column and sealed value
	// agree and the read does not refuse.
	stdout, _ = fixture.runOK("", "show", "api/legacy")
	assert.Equal(t, "FAKELEGACY", decode(t, stdout)["envName"], "the newline must be stripped from the stored env name")
}

// TestMigratePreservesVersionShapes covers L3. A migration must re-seal
// an expiry-bearing secret, a disabled version, and a soft-deleted
// secret, while skipping a destroyed version whose envelope is NULL. The
// prior migration test covered only one enabled env-named version, so
// the state != destroyed AND envelope IS NOT NULL skip clause had no test.
func TestMigratePreservesVersionShapes(t *testing.T) {
	fixture := newCLIFixture(t)

	// An expiry-bearing secret. The expiry must stay bound through migration.
	fixture.runOK(fakeValueOne+"\n", "set", "api/expiry", "--expires", "2030-01-01T00:00:00Z")

	// A multi-version secret with the older version disabled.
	fixture.runOK(fakeValueOne+"\n", "set", "api/multi")
	fixture.runOK(fakeValueTwo+"\n", "set", "api/multi")
	fixture.runOK("", "disable", "api/multi", "1")

	// A soft-deleted secret keeps its envelope, so it still migrates.
	fixture.runOK(fakeValueThree+"\n", "set", "api/deleted")
	fixture.runOK("", "delete", "api/deleted")

	// A purged secret has a destroyed version with a NULL envelope, which
	// the migration must skip.
	fixture.runOK(fakeValueOne+"\n", "set", "api/purged")
	fixture.runOK("", "purge", "api/purged", "--yes")

	downgradeToV1(t, fixture)

	stdout, _ := fixture.runOK("", "migrate")
	assert.InDelta(t, 4, decode(t, stdout)["migratedVersions"], 0,
		"every non-destroyed envelope migrates, the destroyed one is skipped")

	// The expiry-bearing secret reads back and keeps its expiry bound.
	assert.Equal(t, fakeValueOne, fixture.revealValue("api/expiry"))

	stdout, _ = fixture.runOK("", "show", "api/expiry")
	assert.NotNil(t, decode(t, stdout)["expiresAt"], "the expiry must survive migration")

	// The multi-version secret resolves its newest enabled version.
	assert.Equal(t, fakeValueTwo, fixture.revealValue("api/multi"))

	// The purged secret stays destroyed with no recoverable value.
	stdout, _ = fixture.runOK("", "show", "api/purged")

	versions, ok := decode(t, stdout)["versions"].([]any)
	require.True(t, ok)
	require.Len(t, versions, 1)

	version, ok := versions[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "destroyed", version["state"], "the purged version stays destroyed after migration")

	// The soft-deleted secret revives and reads through the new frame.
	fixture.runOK(fakeValueThree+"\n", "set", "api/deleted")
	assert.Equal(t, fakeValueThree, fixture.revealValue("api/deleted"))
}

// TestMigrateRefusesSwappedRecipient covers I1. migrate re-seals every
// envelope, so it must make the same recipient check every read verb
// makes. A format 1 vault whose stored recipient was swapped is refused
// before any re-seal, rather than quietly re-sealing to the loaded
// identity and leaving the swap to surface on a later read.
func TestMigrateRefusesSwappedRecipient(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	downgradeToV1(t, fixture)

	attacker, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	swapVaultRecipient(t, fixture.vaultPath, attacker.Recipient().String())

	_, _, err = fixture.run("", "migrate")
	require.ErrorIs(t, err, vault.ErrRecipientMismatch)
}

// TestSetClearsExpiry covers B-3: an explicit empty --expires removes an
// existing expiry instead of silently keeping it.
func TestSetClearsExpiry(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "exp/clear", "--expires", "2020-01-01")

	stdout, _ := fixture.runOK("", "show", "exp/clear")
	require.NotNil(t, decode(t, stdout)["expiresAt"], "expiry must be set first")

	fixture.runOK(fakeValueTwo+"\n", "set", "exp/clear", "--expires", "")

	stdout, _ = fixture.runOK("", "show", "exp/clear")
	assert.Nil(t, decode(t, stdout)["expiresAt"], "empty --expires must clear the expiry")
}

// TestSetClearsEnvName covers B-08: an explicit empty --env-name removes
// the env name, so exec stops injecting the variable. This is a
// different code path from the expiry clearing, guarded separately.
func TestSetClearsEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "env/clear", "--env-name", "FAKE_CLEARABLE")

	stdout, _ := fixture.runOK("", "show", "env/clear")
	require.Equal(t, "FAKE_CLEARABLE", decode(t, stdout)["envName"], "env name must be set first")

	injected, _ := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_CLEARABLE"`)
	require.Equal(t, fakeValueOne, injected, "exec must inject the env-named secret")

	fixture.runOK(fakeValueTwo+"\n", "set", "env/clear", "--env-name", "")

	stdout, _ = fixture.runOK("", "show", "env/clear")
	assert.Nil(t, decode(t, stdout)["envName"], "empty --env-name must clear the env name")

	after, _ := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_CLEARABLE"`)
	assert.Empty(t, after, "a cleared env name must not inject")
}

// TestRevealJSONBase64EncodesNonUTF8 covers A-5: a value that is not
// valid UTF-8 is base64-encoded and marked, so a consumer gets the
// exact bytes back instead of U+FFFD substitutions.
func TestRevealJSONBase64EncodesNonUTF8(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("\xff\xfe\xfa\n", "set", "bin/blob")

	stdout, stderr := fixture.runOK("", "reveal", "bin/blob")
	obj := decode(t, stdout)

	assert.Equal(t, encodingBase64, obj["encoding"])
	assert.Contains(t, stderr, "base64")

	value, ok := obj["value"].(string)
	require.True(t, ok)

	decoded, err := base64.StdEncoding.DecodeString(value)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xff, 0xfe, 0xfa}, decoded)
}

// TestExecSignalDeathMapsToShellCode covers B-8: a child killed by a
// signal exits 128 plus the signal number, matching shell convention.
func TestExecSignalDeathMapsToShellCode(t *testing.T) {
	fixture := newCLIFixture(t)

	_, _, err := fixture.run("", "exec", "--", "sh", "-c", "kill -KILL $$")

	var exit exitCodeError

	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 137, exit.code, "SIGKILL death must map to 128+9")
}

// TestRekeyRefusesWhileIdentityLockIsHeld pins the concurrent-rekey
// guard: while one identity operation holds the lock, a second rekey
// refuses up front instead of deleting the first one's staged key and
// destroying the only key that reads the vault. passwd shares the same
// lock, so one refusal test covers the serialization for both verbs.
func TestRekeyRefusesWhileIdentityLockIsHeld(t *testing.T) {
	fixture := newCLIFixture(t)

	unlock, err := acquireIdentityLock(fixture.identityPath)
	require.NoError(t, err)

	t.Cleanup(unlock)

	_, _, err = fixture.run("", "rekey")

	require.Error(t, err)
	assert.ErrorContains(t, err, "another safetybox rekey or passwd is running")
}

// TestRekeyRunsAfterLockIsReleased pins that the lock is advisory and
// transient: once the holder releases it, a rekey proceeds normally.
func TestRekeyRunsAfterLockIsReleased(t *testing.T) {
	fixture := newCLIFixture(t)

	unlock, err := acquireIdentityLock(fixture.identityPath)
	require.NoError(t, err)

	unlock()

	fixture.runOK("", "rekey")
}

// TestRekeyPreservesBoundMetadata covers M4. rekey re-seals every version
// with the bound metadata that envelope.Open returns, so an env-named,
// expiring secret must still read after rotation. The prior rekey
// round-trip used a bare secret, so verifyBound compared empty to empty
// and a dropped bound would have shipped green. Here get, reveal, and
// exec all exercise the bound after a rekey, so losing it in the reseal
// would refuse the reads with ErrMetadataTampered.
func TestRekeyPreservesBoundMetadata(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/rot",
		"--env-name", "FAKE_ROT", "--expires", "2030-01-01T00:00:00Z")

	fixture.runOK("", "rekey")

	// get verifies the sealed env name and expiry against the columns, so
	// it would refuse if the reseal dropped either.
	_, _, err := fixture.run("", "get", "api/rot")
	require.NoError(t, err, "get must not refuse an env-named, expiring secret after rekey")

	// reveal returns the original value through the rotated identity.
	assert.Equal(t, fakeValueOne, fixture.revealValue("api/rot"))

	// exec injects the env-named secret, so the sealed env name survived.
	stdout, _ := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_ROT"`)
	assert.Equal(t, fakeValueOne, stdout, "the env name and value must survive rekey")
}

// TestFailedRekeyKeepsStagedKeyOnAmbiguousCommit covers R-7: when the
// rekey commit itself errors, the commit may still have landed in the
// WAL, so the staged key must survive and the error must tell the user
// to test which key opens the vault.
func TestFailedRekeyKeepsStagedKeyOnAmbiguousCommit(t *testing.T) {
	tmp := t.TempDir()
	stagedPath := filepath.Join(tmp, "identity.age.new")

	require.NoError(t, os.WriteFile(stagedPath, []byte("fake-staged-key-not-real"), 0o600))

	failure := fmt.Errorf("commit rekey: %w", vault.ErrCommitAmbiguous)

	err := cleanUpFailedRekey(failure, filepath.Join(tmp, "identity.age"), stagedPath)

	require.Error(t, err)
	require.ErrorContains(t, err, "test which key opens the vault")
	assert.FileExists(t, stagedPath, "an ambiguous commit must not delete the staged key")
}

// TestFailedRekeyRemovesStagedKeyOnPreCommitError pins the other half:
// a failure before the commit leaves the vault unchanged, so the
// staged key is removed to keep a retry clean.
func TestFailedRekeyRemovesStagedKeyOnPreCommitError(t *testing.T) {
	tmp := t.TempDir()
	stagedPath := filepath.Join(tmp, "identity.age.new")

	require.NoError(t, os.WriteFile(stagedPath, []byte("fake-staged-key-not-real"), 0o600))

	err := cleanUpFailedRekey(errors.New("reseal failed"), filepath.Join(tmp, "identity.age"), stagedPath)

	require.Error(t, err)
	assert.NoFileExists(t, stagedPath, "a pre-commit failure must remove the staged key")
}

// TestPromoteStagedIdentityToleratesCompletedHeal covers A-4 and B-06:
// a read verb's heal can promote the staged key between the swap's two
// renames. A missing staged file with the identity already in place is
// that heal having finished the swap, not a failure.
func TestPromoteStagedIdentityToleratesCompletedHeal(t *testing.T) {
	t.Run("renames the staged key into place", func(t *testing.T) {
		tmp := t.TempDir()
		staged := filepath.Join(tmp, "identity.age.new")
		target := filepath.Join(tmp, "identity.age")

		require.NoError(t, os.WriteFile(staged, []byte("fake-staged-key-not-real"), 0o600))

		require.NoError(t, promoteStagedIdentity(staged, target))
		assert.FileExists(t, target)
		assert.NoFileExists(t, staged)
	})

	t.Run("tolerates a heal that already promoted the key", func(t *testing.T) {
		tmp := t.TempDir()
		staged := filepath.Join(tmp, "identity.age.new")
		target := filepath.Join(tmp, "identity.age")

		require.NoError(t, os.WriteFile(target, []byte("fake-key-not-real"), 0o600))

		assert.NoError(t, promoteStagedIdentity(staged, target))
		assert.FileExists(t, target)
	})

	t.Run("fails when neither staged nor identity exists", func(t *testing.T) {
		tmp := t.TempDir()
		staged := filepath.Join(tmp, "identity.age.new")
		target := filepath.Join(tmp, "identity.age")

		require.Error(t, promoteStagedIdentity(staged, target))
	})
}

// TestAcquireIdentityLockMissingDirHintsInit covers B-04: the lock is
// taken before the identity load, so a first-run passwd or rekey with
// no config directory must still surface the init hint, not a raw
// error about a missing lock file.
func TestAcquireIdentityLockMissingDirHintsInit(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nodir", "identity.age")

	_, err := acquireIdentityLock(missing)

	require.Error(t, err)
	require.ErrorIs(t, err, identity.ErrNotFound)
}

// TestIdentityLockPathResolvesSymlink covers A-3: a symlink alias of the
// identity must derive the same lock path as the real file, so two
// spellings serialize against each other instead of taking two locks.
func TestIdentityLockPathResolvesSymlink(t *testing.T) {
	tmp := t.TempDir()
	realPath := filepath.Join(tmp, "identity.age")

	require.NoError(t, os.WriteFile(realPath, []byte("fake-key-not-real"), 0o600))

	alias := filepath.Join(tmp, "alias.age")
	require.NoError(t, os.Symlink(realPath, alias))

	assert.Equal(t, identityLockPath(realPath), identityLockPath(alias),
		"a symlink alias must derive the same lock path as the real identity")
}

// pipeWithInput returns the read end of a pipe holding input. Closing
// the write end models the terminal reaching end of input.
func pipeWithInput(t *testing.T, input string) *os.File {
	t.Helper()

	readEnd, writeEnd, err := os.Pipe()
	require.NoError(t, err)

	t.Cleanup(func() { _ = readEnd.Close() })

	_, err = writeEnd.WriteString(input)
	require.NoError(t, err)
	require.NoError(t, writeEnd.Close())

	return readEnd
}

// TestReadLineWipingStopsAtNewline pins that the prompt line reader
// returns exactly the typed line, without its newline, and never
// consumes input past it.
func TestReadLineWipingStopsAtNewline(t *testing.T) {
	readEnd := pipeWithInput(t, "fake-typed-passphrase-not-real\nnext")

	line, err := readLineWiping(int(readEnd.Fd()))

	require.NoError(t, err)
	assert.Equal(t, []byte("fake-typed-passphrase-not-real"), line)

	rest, err := io.ReadAll(readEnd)
	require.NoError(t, err)
	assert.Equal(t, "next", string(rest), "input after the newline must stay unread")
}

// TestReadLineWipingReturnsDataAtEndOfInput pins that input ending
// without a newline still yields the line, matching term.ReadPassword.
func TestReadLineWipingReturnsDataAtEndOfInput(t *testing.T) {
	readEnd := pipeWithInput(t, "fake-typed-passphrase-not-real")

	line, err := readLineWiping(int(readEnd.Fd()))

	require.NoError(t, err)
	assert.Equal(t, []byte("fake-typed-passphrase-not-real"), line)
}

// TestReadLineWipingSurvivesGrowth pins content fidelity for a line
// longer than the reader's initial buffer, so the wiping of outgrown
// buffers never corrupts a long passphrase.
func TestReadLineWipingSurvivesGrowth(t *testing.T) {
	long := strings.Repeat("x", 700)
	readEnd := pipeWithInput(t, long+"\n")

	line, err := readLineWiping(int(readEnd.Fd()))

	require.NoError(t, err)
	assert.Equal(t, []byte(long), line)
}
