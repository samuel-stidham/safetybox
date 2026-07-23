package vault_test

import (
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/samuel-stidham/safetybox/v3/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestMigrateAlreadyCurrentFormat pins that migrating a vault already at
// the current format is a clean no-op, so a re-run after a crash reaches
// it without re-sealing anything.
func TestMigrateAlreadyCurrentFormat(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(t.Context(), path, fakeRecipient))

	_, err := vault.Migrate(t.Context(), path, fakeRecipient,
		func(string, int64, string, string, []byte) ([]byte, string, error) {
			return nil, "", errors.New("reseal must not run for a current vault")
		})
	require.ErrorIs(t, err, vault.ErrAlreadyCurrentFormat)
}

// TestMigrateMissingVault reports a not-found vault clearly.
func TestMigrateMissingVault(t *testing.T) {
	_, err := vault.Migrate(t.Context(), vaultPath(t), fakeRecipient,
		func(string, int64, string, string, []byte) ([]byte, string, error) {
			return nil, "", nil
		})
	require.ErrorIs(t, err, vault.ErrVaultNotFound)
}

// stampFormatVersion rewrites the vault's stored format version through a
// direct handle, standing in for an older on-disk format.
func stampFormatVersion(t *testing.T, path, version string) {
	t.Helper()

	handle, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	_, err = handle.ExecContext(t.Context(),
		"UPDATE vault_meta SET value = ? WHERE key = 'format_version'", version)
	require.NoError(t, err)
}

// TestConcurrentMigrateLoserGetsAlreadyCurrent covers L2. Two migrate
// runs both pass the pre-transaction format check, then serialize on the
// SQLite write lock. Without the in-transaction re-check the loser would
// re-seal the winner's version 2 frames and fail with an address
// mismatch. The re-check makes it report a clean already-current no-op
// instead, and the vault ends at the current format with the secret
// intact.
func TestConcurrentMigrateLoserGetsAlreadyCurrent(t *testing.T) {
	path := vaultPath(t)

	require.NoError(t, vault.Create(t.Context(), path, fakeRecipient))

	// Append a version, then stamp the format back to 1 so migrate has
	// work to do. The fake envelope stands in for a legacy frame, since
	// the reseal callback never decrypts it.
	opened, err := vault.Open(t.Context(), path)
	require.NoError(t, err)

	_, err = opened.AppendVersion(t.Context(), "api/one", vault.SetOptions{},
		func(address, _, _ string) ([]byte, error) {
			return []byte("legacy:" + address), nil
		})
	require.NoError(t, err)
	require.NoError(t, opened.Close())

	stampFormatVersion(t, path, "1")

	reseal := func(_ string, _ int64, _, _ string, old []byte) ([]byte, string, error) {
		return append([]byte("resealed:"), old...), "", nil
	}

	// The winner signals once it is inside its write transaction, then
	// holds the lock so the loser starts and blocks on it deterministically.
	started := make(chan struct{})

	var (
		waitGroup   sync.WaitGroup
		winnerCount int64
		winnerErr   error
		loserErr    error
	)

	waitGroup.Add(2)

	go func() {
		defer waitGroup.Done()

		winnerCount, winnerErr = vault.Migrate(t.Context(), path, fakeRecipient,
			func(name string, number int64, envName, expiresAt string, old []byte) ([]byte, string, error) {
				select {
				case <-started:
				default:
					close(started)
				}

				time.Sleep(300 * time.Millisecond)

				return reseal(name, number, envName, expiresAt, old)
			})
	}()

	go func() {
		defer waitGroup.Done()

		<-started

		_, loserErr = vault.Migrate(t.Context(), path, fakeRecipient, reseal)
	}()

	waitGroup.Wait()

	require.NoError(t, winnerErr, "the winner must migrate cleanly")
	assert.Equal(t, int64(1), winnerCount)
	require.ErrorIs(t, loserErr, vault.ErrAlreadyCurrentFormat,
		"the loser must report already current, not an address mismatch")

	reopened, err := vault.Open(t.Context(), path)
	require.NoError(t, err)

	defer func() { require.NoError(t, reopened.Close()) }()

	newest, err := reopened.NewestEnabled(t.Context(), "api/one")
	require.NoError(t, err)
	assert.Contains(t, string(newest.Envelope), "resealed:", "the winner's reseal must persist")
}
