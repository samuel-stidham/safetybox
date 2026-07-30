package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLockOpenRefusesASymlinkedLockPath pins the first half of GitHub
// issue #12. The lock file was opened without O_NOFOLLOW, so a symlink
// planted at the .lock path redirected the file this creates. Planting
// one needs write access to the 0700 directory, so this is hardening
// rather than a reachable hole.
func TestLockOpenRefusesASymlinkedLockPath(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "redirected")
	lockPath := filepath.Join(directory, "vault.db.lock")

	require.NoError(t, os.Symlink(target, lockPath))

	_, err := flockExclusiveNB(lockPath, "busy", vault.ErrVaultNotFound)

	require.Error(t, err, "a symlinked lock path must be refused")
	assert.NoFileExists(t, target, "the open must not create the symlink's target")
}

// TestLockOpenStillWorksOnARegularPath guards against O_NOFOLLOW breaking
// the normal case, including a second acquisition after release.
func TestLockOpenStillWorksOnARegularPath(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "vault.db.lock")

	unlock, err := flockExclusiveNB(lockPath, "busy", vault.ErrVaultNotFound)
	require.NoError(t, err)
	assert.FileExists(t, lockPath)

	unlock()

	// The lock file is left behind on purpose, so a second run must be
	// able to lock the existing inode rather than need a fresh one.
	again, err := flockExclusiveNB(lockPath, "busy", vault.ErrVaultNotFound)
	require.NoError(t, err, "an existing lock file must still be lockable")

	again()
}

// TestMigrateLeavesNoStrayLockFileWhenVaultIsMissing pins the second half
// of issue #12. acquireMigrateLock ran before any vault existence check,
// so migrate against a missing vault in an existing directory created an
// empty vault.db.lock that nothing removed. Deleting it afterwards is not
// an option, since removing lock files reopens the fresh-inode race, so
// the fix is to refuse before locking.
func TestMigrateLeavesNoStrayLockFileWhenVaultIsMissing(t *testing.T) {
	fixture := newCLIFixture(t)

	// An existing directory with no vault in it, which is the shape that
	// produced the stray file.
	directory := t.TempDir()
	missingVault := filepath.Join(directory, "vault.db")

	stdout, stderr, err := fixture.run("", "migrate", "--vault", missingVault)

	require.Error(t, err, "migrate must refuse when no vault exists")
	require.ErrorIs(t, err, vault.ErrVaultNotFound)
	assert.Contains(t, err.Error(), "safetybox init")

	assert.NoFileExists(t, missingVault+".lock",
		"a refused migrate must not leave a lock file behind")

	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "the directory must be left exactly as it was")

	assert.Empty(t, stdout)
	assert.NotContains(t, stderr, "panic")
}

// TestMigrateRefusesANonRegularVaultPath covers the other shape the stat
// can find. A directory or FIFO at the vault path is not a vault, and
// reporting that before locking keeps the same no-stray-file guarantee.
func TestMigrateRefusesANonRegularVaultPath(t *testing.T) {
	fixture := newCLIFixture(t)

	directory := filepath.Join(t.TempDir(), "vault.db")
	require.NoError(t, os.Mkdir(directory, 0o700))

	_, _, err := fixture.run("", "migrate", "--vault", directory)

	require.Error(t, err)
	require.ErrorIs(t, err, vault.ErrVaultCorrupt)
	assert.NoFileExists(t, directory+".lock",
		"a refused migrate must not leave a lock file behind")
}
