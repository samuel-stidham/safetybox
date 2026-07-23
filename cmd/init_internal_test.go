package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samuel-stidham/safetybox/v2/internal/vault"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePassphrase is obviously fake test material, never a real secret.
const fakePassphrase = "fake-test-passphrase-not-real"

func runInitOnce(t *testing.T, identityPath, vaultPath, passphraseFile string) (string, error) {
	t.Helper()

	root := newRootCmd("test")
	root.SetArgs([]string{
		initVerb,
		"--identity", identityPath,
		"--vault", vaultPath,
		"--passphrase-file", passphraseFile,
	})

	var stderr bytes.Buffer

	root.SetOut(io.Discard)
	root.SetErr(&stderr)

	err := root.Execute()

	return stderr.String(), err
}

func TestInitEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	identityPath := filepath.Join(tmp, "config", "identity.age")
	vaultPath := filepath.Join(tmp, "data", "vault.db")
	passphraseFile := filepath.Join(tmp, "passphrase")

	require.NoError(t, os.WriteFile(passphraseFile, []byte(fakePassphrase+"\n"), 0o600))

	stderr, err := runInitOnce(t, identityPath, vaultPath, passphraseFile)
	require.NoError(t, err)

	// The identity file exists with ssh-style permissions.
	fileInfo, err := os.Stat(identityPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

	dirInfo, err := os.Stat(filepath.Dir(identityPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	// The vault opens and stores a parseable recipient.
	openedVault, err := vault.Open(t.Context(), vaultPath)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, openedVault.Close()) })

	recipient, err := openedVault.Recipient(t.Context())
	require.NoError(t, err)

	_, err = age.ParseX25519Recipient(recipient)
	require.NoError(t, err)

	// The identity file decrypts with the passphrase, trailing
	// newline trimmed, back to an age secret key.
	scryptIdentity, err := age.NewScryptIdentity(fakePassphrase)
	require.NoError(t, err)

	sealed, err := os.ReadFile(filepath.Clean(identityPath))
	require.NoError(t, err)

	reader, err := age.Decrypt(bytes.NewReader(sealed), scryptIdentity)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(decrypted), "AGE-SECRET-KEY-"))

	// The recipient and the backup warning went to stderr.
	assert.Contains(t, stderr, recipient)
	assert.Contains(t, stderr, "BACK UP")
}

func TestInitRefusesExistingIdentity(t *testing.T) {
	tmp := t.TempDir()
	identityPath := filepath.Join(tmp, "config", "identity.age")
	vaultPath := filepath.Join(tmp, "data", "vault.db")
	passphraseFile := filepath.Join(tmp, "passphrase")

	require.NoError(t, os.WriteFile(passphraseFile, []byte(fakePassphrase), 0o600))

	_, err := runInitOnce(t, identityPath, vaultPath, passphraseFile)
	require.NoError(t, err)

	_, err = runInitOnce(t, identityPath, filepath.Join(tmp, "data", "other.db"), passphraseFile)
	require.ErrorContains(t, err, "refusing to overwrite")
}

func TestInitRefusesEmptyPassphraseFile(t *testing.T) {
	tmp := t.TempDir()
	passphraseFile := filepath.Join(tmp, "passphrase")

	require.NoError(t, os.WriteFile(passphraseFile, []byte("\n"), 0o600))

	_, err := runInitOnce(t,
		filepath.Join(tmp, "config", "identity.age"),
		filepath.Join(tmp, "data", "vault.db"),
		passphraseFile)
	require.ErrorContains(t, err, "empty")
}

func TestInitTrimsCRLFFromPassphraseFile(t *testing.T) {
	tmp := t.TempDir()
	identityPath := filepath.Join(tmp, "config", "identity.age")
	passphraseFile := filepath.Join(tmp, "passphrase")

	require.NoError(t, os.WriteFile(passphraseFile, []byte(fakePassphrase+"\r\n"), 0o600))

	_, err := runInitOnce(t, identityPath, filepath.Join(tmp, "data", "vault.db"), passphraseFile)
	require.NoError(t, err)

	// The identity must decrypt with the passphrase minus the CRLF.
	scryptIdentity, err := age.NewScryptIdentity(fakePassphrase)
	require.NoError(t, err)

	sealed, err := os.ReadFile(filepath.Clean(identityPath))
	require.NoError(t, err)

	_, err = age.Decrypt(bytes.NewReader(sealed), scryptIdentity)
	require.NoError(t, err)
}

func TestInitMissingPassphraseFile(t *testing.T) {
	tmp := t.TempDir()

	_, err := runInitOnce(t,
		filepath.Join(tmp, "config", "identity.age"),
		filepath.Join(tmp, "data", "vault.db"),
		filepath.Join(tmp, "does-not-exist"))
	require.ErrorContains(t, err, "passphrase file")
}

func TestInitWithoutPassphraseFileNeedsTerminal(t *testing.T) {
	// Test processes have no TTY on stdin, so the interactive prompt
	// must refuse and point at --passphrase-file.
	tmp := t.TempDir()

	root := newRootCmd("test")
	root.SetArgs([]string{
		initVerb,
		"--identity", filepath.Join(tmp, "config", "identity.age"),
		"--vault", filepath.Join(tmp, "data", "vault.db"),
	})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	err := root.Execute()
	require.ErrorContains(t, err, "--passphrase-file")
}

func TestInitRemovesIdentityWhenVaultCreateFails(t *testing.T) {
	tmp := t.TempDir()
	identityPath := filepath.Join(tmp, "config", "identity.age")
	vaultPath := filepath.Join(tmp, "data", "vault.db")
	passphraseFile := filepath.Join(tmp, "passphrase")

	require.NoError(t, os.WriteFile(passphraseFile, []byte(fakePassphrase), 0o600))

	// Pre-create the vault so vault.Create refuses.
	require.NoError(t, os.MkdirAll(filepath.Dir(vaultPath), 0o700))
	require.NoError(t, os.WriteFile(vaultPath, []byte("occupied"), 0o600))

	_, err := runInitOnce(t, identityPath, vaultPath, passphraseFile)
	require.Error(t, err)

	// The freshly written identity must be cleaned up so init stays
	// retryable.
	_, statErr := os.Stat(identityPath)
	require.True(t, os.IsNotExist(statErr), "identity file must be removed on vault failure")
}
