package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	_, err = handle.ExecContext(context.Background(),
		"UPDATE vault_meta SET value = ? WHERE key = 'recipient'", recipient)
	require.NoError(t, err)
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
