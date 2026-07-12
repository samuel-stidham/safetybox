package vault_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/samuel-stidham/safetybox/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// fakeRecipient is obviously fake test material, never a real key.
const fakeRecipient = "age1fake-recipient-for-tests-not-real"

func vaultPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(t.TempDir(), "safetybox", "vault.db")
}

func TestCreateAndOpen(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	opened, err := vault.Open(path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, opened.Close()) })

	recipient, err := opened.Recipient()
	require.NoError(t, err)
	assert.Equal(t, fakeRecipient, recipient)
	assert.Equal(t, path, opened.Path())
}

func TestCreateSetsRestrictivePermissions(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm(), "vault file must be 0600")

	dirInfo, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(), "vault directory must be 0700")
}

func TestCreateRefusesExistingVault(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	err := vault.Create(path, fakeRecipient)
	require.ErrorIs(t, err, vault.ErrVaultExists)
}

func TestOpenMissingVault(t *testing.T) {
	_, err := vault.Open(vaultPath(t))
	require.ErrorIs(t, err, vault.ErrVaultNotFound)
}

func TestOpenRejectsUnknownFormatVersion(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	raw, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)

	_, err = raw.ExecContext(context.Background(),
		"UPDATE vault_meta SET value = '999' WHERE key = 'format_version'")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	_, err = vault.Open(path)
	require.ErrorIs(t, err, vault.ErrFormatVersion)
}

func TestCreateUsesWALAndSchemaV1(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	raw, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, raw.Close()) })

	var journalMode string

	row := raw.QueryRowContext(context.Background(), "PRAGMA journal_mode")
	require.NoError(t, row.Scan(&journalMode))
	assert.Equal(t, "wal", journalMode)

	for _, table := range []string{"vault_meta", "secret", "secret_version"} {
		var name string

		row := raw.QueryRowContext(context.Background(),
			"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table)
		require.NoError(t, row.Scan(&name), "table %s must exist", table)
	}
}

func TestOpenRejectsForeignDatabase(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))

	raw, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)

	_, err = raw.ExecContext(context.Background(), "CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	_, err = vault.Open(path)
	require.Error(t, err, "a sqlite file without vault_meta is not a vault")
}

func TestOpenRejectsGarbageFile(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("this is not a sqlite database"), 0o600))

	_, err := vault.Open(path)
	require.Error(t, err)
}

func TestSchemaRejectsInvalidState(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	raw, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, raw.Close()) })

	ctx := context.Background()

	_, err = raw.ExecContext(ctx,
		`INSERT INTO secret (name, created_at, updated_at) VALUES ('testing/fake', '2026-01-01', '2026-01-01')`)
	require.NoError(t, err)

	_, err = raw.ExecContext(ctx,
		`INSERT INTO secret_version (secret_id, version_number, state, created_at)
		 VALUES (1, 1, 'bogus', '2026-01-01')`)
	require.Error(t, err, "state CHECK constraint must reject unknown states")
}
