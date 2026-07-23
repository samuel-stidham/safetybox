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

	"github.com/samuel-stidham/safetybox/v2/internal/identity"
	"github.com/samuel-stidham/safetybox/v2/internal/vault"

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

	_, err = handle.ExecContext(t.Context(),
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
