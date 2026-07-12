package identity_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samuel-stidham/safetybox/internal/identity"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePassphrase is obviously fake test material, never a real secret.
const fakePassphrase = "fake-identity-test-passphrase"

func newKey(t *testing.T) *age.X25519Identity {
	t.Helper()

	key, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	return key
}

func identityPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(t.TempDir(), "config", "identity.age")
}

func TestWriteLoadRoundTrip(t *testing.T) {
	path := identityPath(t)
	key := newKey(t)

	require.NoError(t, identity.Write(path, key, []byte(fakePassphrase)))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	loaded, cleanup, err := identity.Load(path, []byte(fakePassphrase))
	require.NoError(t, err)

	defer cleanup()

	assert.Equal(t, key.Recipient().String(), loaded.Recipient().String())
}

func TestLoadMissingFile(t *testing.T) {
	_, _, err := identity.Load(identityPath(t), []byte(fakePassphrase))
	require.ErrorIs(t, err, identity.ErrNotFound)
}

func TestLoadRefusesOpenPermissions(t *testing.T) {
	path := identityPath(t)

	require.NoError(t, identity.Write(path, newKey(t), []byte(fakePassphrase)))

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		require.NoError(t, os.Chmod(path, mode))

		_, _, err := identity.Load(path, []byte(fakePassphrase))
		require.ErrorIs(t, err, identity.ErrUnsafePermissions, "mode %04o must be refused", mode)
	}
}

func TestLoadWrongPassphrase(t *testing.T) {
	path := identityPath(t)

	require.NoError(t, identity.Write(path, newKey(t), []byte(fakePassphrase)))

	_, _, err := identity.Load(path, []byte("fake-wrong-passphrase"))
	require.ErrorIs(t, err, identity.ErrDecryptFailed)
}

func TestLoadMalformedContent(t *testing.T) {
	path := identityPath(t)

	// Valid age encryption wrapping something that is not a key.
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))

	recipient, err := age.NewScryptRecipient(fakePassphrase)
	require.NoError(t, err)

	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	require.NoError(t, err)

	writer, err := age.Encrypt(file, recipient)
	require.NoError(t, err)

	_, err = writer.Write([]byte("not an age secret key"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, file.Close())

	_, _, err = identity.Load(path, []byte(fakePassphrase))
	require.ErrorIs(t, err, identity.ErrMalformed)
}

func TestWriteRefusesOverwrite(t *testing.T) {
	path := identityPath(t)

	require.NoError(t, identity.Write(path, newKey(t), []byte(fakePassphrase)))
	require.ErrorIs(t, identity.Write(path, newKey(t), []byte(fakePassphrase)), identity.ErrExists)
}

func TestReplaceSwapsPassphrase(t *testing.T) {
	path := identityPath(t)
	key := newKey(t)

	require.NoError(t, identity.Write(path, key, []byte(fakePassphrase)))
	require.NoError(t, identity.Replace(path, key, []byte("fake-new-passphrase")))

	_, _, err := identity.Load(path, []byte(fakePassphrase))
	require.ErrorIs(t, err, identity.ErrDecryptFailed, "old passphrase must stop working")

	loaded, cleanup, err := identity.Load(path, []byte("fake-new-passphrase"))
	require.NoError(t, err)

	defer cleanup()

	assert.Equal(t, key.Recipient().String(), loaded.Recipient().String())
}
