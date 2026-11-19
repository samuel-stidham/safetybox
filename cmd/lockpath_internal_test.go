package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLockPathConvergesForAliasSpellings pins the spellings that must
// serialize against each other. lockSiblingPath resolves symlinks and
// absolutises, so every one of these names the same lock file.
func TestLockPathConvergesForAliasSpellings(t *testing.T) {
	directory := t.TempDir()
	vaultPath := filepath.Join(directory, "vault.db")

	require.NoError(t, os.WriteFile(vaultPath, []byte("fake"), 0o600))

	symlinkPath := filepath.Join(directory, "alias.db")
	require.NoError(t, os.Symlink(vaultPath, symlinkPath))

	canonical := lockSiblingPath(vaultPath)

	for _, spelling := range []struct {
		name string
		path string
	}{
		{name: "symlink", path: symlinkPath},
		{name: "redundant separators", path: filepath.Join(directory, ".", "vault.db")},
		{name: "parent traversal", path: filepath.Join(directory, "sub", "..", "vault.db")},
	} {
		t.Run(spelling.name, func(t *testing.T) {
			assert.Equal(t, canonical, lockSiblingPath(spelling.path),
				"%s must lock the same file as the canonical path", spelling.name)
		})
	}
}

// TestLockPathDivergesForHardlinks records the known limit in GitHub
// issue #11 rather than asserting a fix.
//
// The lock is keyed by path. Two hardlinks to one file are two paths, so
// each derives its own lock file and both runs lock at once. Keying to
// the inode would mean flocking the database itself, and mixing flock
// with SQLite's POSIX locks carries platform risk judged not worth it
// for a single-user tool where the aliasing is self-inflicted. The limit
// is documented in the security model of the safetybox-docs site.
//
// This test exists so the behaviour is visible and tracked. If someone
// later makes hardlinks converge, this test fails and points at the doc
// and the issue, which is the prompt to update both.
func TestLockPathDivergesForHardlinks(t *testing.T) {
	directory := t.TempDir()
	vaultPath := filepath.Join(directory, "vault.db")

	require.NoError(t, os.WriteFile(vaultPath, []byte("fake"), 0o600))

	hardlinkPath := filepath.Join(directory, "same-inode.db")
	require.NoError(t, os.Link(vaultPath, hardlinkPath))

	// Same inode, confirming this really is a hardlink rather than a copy.
	original, err := os.Stat(vaultPath)
	require.NoError(t, err)

	linked, err := os.Stat(hardlinkPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(original, linked), "the probe must be a real hardlink")

	assert.NotEqual(t, lockSiblingPath(vaultPath), lockSiblingPath(hardlinkPath),
		"known limit, issue #11: hard-linked spellings derive separate locks. "+
			"If this now converges, update the security model in safetybox-docs and close the issue")
}

// TestBothHardlinkSpellingsCanLockAtOnce shows the consequence of the
// limit above, so the record is behavioural and not only about strings.
func TestBothHardlinkSpellingsCanLockAtOnce(t *testing.T) {
	directory := t.TempDir()
	vaultPath := filepath.Join(directory, "vault.db")

	require.NoError(t, os.WriteFile(vaultPath, []byte("fake"), 0o600))

	hardlinkPath := filepath.Join(directory, "same-inode.db")
	require.NoError(t, os.Link(vaultPath, hardlinkPath))

	first, err := acquireMigrateLock(vaultPath)
	require.NoError(t, err)

	t.Cleanup(first)

	second, err := acquireMigrateLock(hardlinkPath)
	require.NoError(t, err,
		"known limit, issue #11: the second spelling still acquires a lock")

	t.Cleanup(second)

	// The same spelling is still refused, which is the guarantee that does
	// hold and the one every real invocation relies on.
	_, err = acquireMigrateLock(vaultPath)
	require.Error(t, err, "the same spelling must still serialize")
	assert.ErrorContains(t, err, "another safetybox migrate is running")
}
