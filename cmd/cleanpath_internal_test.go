package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uncleanSpelling returns a path that names the same file as path once
// it is cleaned, through a directory that does not exist. The Go runtime
// cleans it before opening a file. The kernel does not, so a rename
// through this spelling fails.
func uncleanSpelling(path string) string {
	return filepath.Dir(path) + string(filepath.Separator) +
		filepath.Join("..", "absent", "..", filepath.Base(filepath.Dir(path)), filepath.Base(path))
}

// TestResolvePathsAreCleaned pins that the flag and the environment
// variable both resolve to one clean spelling.
func TestResolvePathsAreCleaned(t *testing.T) {
	const (
		unclean = "/from/absent/../here/./file"
		clean   = "/from/here/file"
	)

	t.Run("flags", func(t *testing.T) {
		opts := &options{vaultPath: unclean, identityPath: unclean}

		vaultPath, err := opts.resolveVaultPath()
		require.NoError(t, err)
		assert.Equal(t, clean, vaultPath)

		identityPath, err := opts.resolveIdentityPath()
		require.NoError(t, err)
		assert.Equal(t, clean, identityPath)
	})

	t.Run("environment", func(t *testing.T) {
		t.Setenv(envVault, unclean)
		t.Setenv(envIdentity, unclean)

		opts := &options{}

		vaultPath, err := opts.resolveVaultPath()
		require.NoError(t, err)
		assert.Equal(t, clean, vaultPath)

		identityPath, err := opts.resolveIdentityPath()
		require.NoError(t, err)
		assert.Equal(t, clean, identityPath)
	})
}

// TestRekeyCompletesThroughAnUncleanIdentityPath pins the fix for a rekey
// that committed the vault to the new key and then failed the identity
// swap. The identity loaded through the unclean path, because the Go
// runtime cleans it. The swap handed the raw path to rename, which the
// kernel resolved literally and refused. The vault was then sealed to a
// key that sat in the .new sibling, and every read failed.
func TestRekeyCompletesThroughAnUncleanIdentityPath(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	cleanIdentity := fixture.identityPath
	cleanVault := fixture.vaultPath

	fixture.identityPath = uncleanSpelling(cleanIdentity)
	fixture.vaultPath = uncleanSpelling(cleanVault)

	require.NotEqual(t, cleanIdentity, fixture.identityPath)

	stdout, _ := fixture.runOK("", "rekey")

	assert.Equal(t, cleanIdentity+".bak", decode(t, stdout)["backupIdentity"],
		"the reported backup path must be the clean spelling")

	_, err := os.Stat(cleanIdentity + ".bak")
	require.NoError(t, err, "the old identity must be kept as the .bak sibling")

	_, err = os.Stat(cleanIdentity + ".new")
	require.ErrorIs(t, err, os.ErrNotExist, "the staged identity must be promoted, not left behind")

	// The vault must read back through both spellings.
	assert.Equal(t, fakeValueOne, fixture.revealValue("api/one"))

	fixture.identityPath = cleanIdentity
	fixture.vaultPath = cleanVault

	assert.Equal(t, fakeValueOne, fixture.revealValue("api/one"))
}
