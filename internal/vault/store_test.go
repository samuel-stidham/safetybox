package vault_test

import (
	"testing"
	"time"

	"github.com/samuel-stidham/safetybox/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSealer returns a fake envelope stamped with its address. The
// vault never inspects envelope bytes, so tests do not need real
// crypto.
func fakeSealer(t *testing.T) vault.Sealer {
	t.Helper()

	return func(address string) ([]byte, error) {
		return []byte("fake-envelope:" + address), nil
	}
}

func openTestVault(t *testing.T) *vault.Vault {
	t.Helper()

	path := vaultPath(t)

	require.NoError(t, vault.Create(path, fakeRecipient))

	opened, err := vault.Open(path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, opened.Close()) })

	return opened
}

func TestAppendVersionCreatesAndIncrements(t *testing.T) {
	testVault := openTestVault(t)

	first, err := testVault.AppendVersion("api/testing/fake", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	assert.Equal(t, int64(1), first.Version.Number)
	assert.Equal(t, vault.StateEnabled, first.Version.State)

	second, err := testVault.AppendVersion("api/testing/fake", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	assert.Equal(t, int64(2), second.Version.Number)
	assert.Zero(t, second.Revoked, "updates must not auto-disable prior versions")

	newest, err := testVault.NewestEnabled("api/testing/fake")
	require.NoError(t, err)
	assert.Equal(t, "api/testing/fake", newest.Secret.Name)
	assert.Equal(t, int64(2), newest.Version.Number)
	assert.Equal(t, []byte("fake-envelope:api/v1/api/testing/fake/2"), newest.Envelope)
}

func TestAppendVersionRevokePrevious(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("rotate/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("rotate/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	third, err := testVault.AppendVersion("rotate/me", vault.SetOptions{RevokePrevious: true}, fakeSealer(t))
	require.NoError(t, err)
	assert.Equal(t, int64(2), third.Revoked)

	_, versions, err := testVault.Meta("rotate/me")
	require.NoError(t, err)
	require.Len(t, versions, 3)
	assert.Equal(t, vault.StateDisabled, versions[0].State)
	assert.Equal(t, vault.StateDisabled, versions[1].State)
	assert.Equal(t, vault.StateEnabled, versions[2].State)
}

func TestAppendVersionRejectsBadNames(t *testing.T) {
	testVault := openTestVault(t)

	for _, name := range []string{"", "/leading", "trailing/", "has space", "new\nline", "double//slash"} {
		_, err := testVault.AppendVersion(name, vault.SetOptions{}, fakeSealer(t))
		require.ErrorIs(t, err, vault.ErrInvalidName, "name %q must be rejected", name)
	}
}

func TestAppendVersionStoresAttributes(t *testing.T) {
	testVault := openTestVault(t)
	envName := "FAKE_TEST_KEY"
	expiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	result, err := testVault.AppendVersion("api/testing/fake",
		vault.SetOptions{EnvName: &envName, ExpiresAt: &expiry}, fakeSealer(t))
	require.NoError(t, err)
	require.NotNil(t, result.Secret.EnvName)
	assert.Equal(t, envName, *result.Secret.EnvName)
	require.NotNil(t, result.Secret.ExpiresAt)
	assert.True(t, expiry.Equal(*result.Secret.ExpiresAt))

	// A later set without attributes keeps them.
	kept, err := testVault.AppendVersion("api/testing/fake", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	require.NotNil(t, kept.Secret.EnvName)
	assert.Equal(t, envName, *kept.Secret.EnvName)
	require.NotNil(t, kept.Secret.ExpiresAt)
}

func TestNewestEnabledSkipsDisabled(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("skip/disabled", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("skip/disabled", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.NoError(t, testVault.Disable("skip/disabled", 2))

	newest, err := testVault.NewestEnabled("skip/disabled")
	require.NoError(t, err)
	assert.Equal(t, int64(1), newest.Version.Number)

	require.NoError(t, testVault.Disable("skip/disabled", 1))

	_, err = testVault.NewestEnabled("skip/disabled")
	require.ErrorIs(t, err, vault.ErrVersionNotFound)
}

func TestNewestEnabledErrors(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.NewestEnabled("missing/secret")
	require.ErrorIs(t, err, vault.ErrSecretNotFound)

	_, err = testVault.AppendVersion("deleted/secret", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	require.NoError(t, testVault.SoftDelete("deleted/secret"))

	_, err = testVault.NewestEnabled("deleted/secret")
	require.ErrorIs(t, err, vault.ErrSecretDeleted)
}

func TestSetRevivesSoftDeletedSecret(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("revive/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	require.NoError(t, testVault.SoftDelete("revive/me"))

	revived, err := testVault.AppendVersion("revive/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	assert.Nil(t, revived.Secret.DeletedAt)
	assert.Equal(t, int64(2), revived.Version.Number, "version numbers survive delete and revive")
}

func TestListAndPrefix(t *testing.T) {
	testVault := openTestVault(t)

	for _, name := range []string{"api/stripe/live", "api/stripe/test", "db/postgres"} {
		_, err := testVault.AppendVersion(name, vault.SetOptions{}, fakeSealer(t))
		require.NoError(t, err)
	}

	require.NoError(t, testVault.SoftDelete("db/postgres"))

	all, err := testVault.List("")
	require.NoError(t, err)
	require.Len(t, all, 2, "deleted secrets stay out of list")

	stripe, err := testVault.List("api/stripe/")
	require.NoError(t, err)
	require.Len(t, stripe, 2)
	assert.Equal(t, "api/stripe/live", stripe[0].Name)
	assert.Equal(t, int64(1), stripe[0].LatestVersion)
}

func TestStale(t *testing.T) {
	testVault := openTestVault(t)
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	_, err := testVault.AppendVersion("expired/secret", vault.SetOptions{ExpiresAt: &past}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("fresh/secret", vault.SetOptions{ExpiresAt: &future}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("eternal/secret", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	stale, err := testVault.Stale(now)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, "expired/secret", stale[0].Name)
	assert.True(t, stale[0].Expired(now))

	// Expired secrets still resolve. Expiry is staleness, never
	// deletion.
	newest, err := testVault.NewestEnabled("expired/secret")
	require.NoError(t, err)
	assert.NotEmpty(t, newest.Envelope)
}

func TestDisableErrors(t *testing.T) {
	testVault := openTestVault(t)

	require.ErrorIs(t, testVault.Disable("missing", 1), vault.ErrSecretNotFound)

	_, err := testVault.AppendVersion("dis/able", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.ErrorIs(t, testVault.Disable("dis/able", 9), vault.ErrVersionNotFound)

	_, err = testVault.Purge("dis/able")
	require.NoError(t, err)

	require.ErrorIs(t, testVault.Disable("dis/able", 1), vault.ErrVersionDestroyed)
}

func TestSoftDeleteTwiceFails(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("del/ete", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.NoError(t, testVault.SoftDelete("del/ete"))
	require.ErrorIs(t, testVault.SoftDelete("del/ete"), vault.ErrSecretDeleted)
}

func TestPurgeDestroysEnvelopes(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("purge/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("purge/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	destroyed, err := testVault.Purge("purge/me")
	require.NoError(t, err)
	assert.Equal(t, int64(2), destroyed)

	meta, versions, err := testVault.Meta("purge/me")
	require.NoError(t, err)
	assert.NotNil(t, meta.DeletedAt, "purge implies delete")

	for _, version := range versions {
		assert.Equal(t, vault.StateDestroyed, version.State)
	}

	_, err = testVault.NewestEnabled("purge/me")
	require.ErrorIs(t, err, vault.ErrSecretDeleted)
}

func TestEntries(t *testing.T) {
	testVault := openTestVault(t)
	envName := "FAKE_STRIPE_KEY"

	_, err := testVault.AppendVersion("api/stripe/live", vault.SetOptions{EnvName: &envName}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("api/stripe/live", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("db/postgres", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	tests := []struct {
		name   string
		filter vault.EntryFilter
		want   []string
	}{
		{
			name:   "zero filter selects everything",
			filter: vault.EntryFilter{},
			want:   []string{"api/stripe/live", "db/postgres"},
		},
		{name: "env filter drops unnamed", filter: vault.EntryFilter{EnvNamed: true}, want: []string{"api/stripe/live"}},
		{name: "prefix filter", filter: vault.EntryFilter{Prefix: "db/"}, want: []string{"db/postgres"}},
		{name: "filters compose to empty", filter: vault.EntryFilter{Prefix: "db/", EnvNamed: true}, want: nil},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			entries, err := testVault.Entries(testCase.filter)
			require.NoError(t, err)
			require.Len(t, entries, len(testCase.want))

			for index, entry := range entries {
				assert.Equal(t, testCase.want[index], entry.Name)
			}
		})
	}

	entries, err := testVault.Entries(vault.EntryFilter{EnvNamed: true})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, envName, entries[0].EnvName)
	assert.Equal(t, int64(2), entries[0].Version, "entries resolve the newest enabled version")

	unnamed, err := testVault.Entries(vault.EntryFilter{Prefix: "db/"})
	require.NoError(t, err)
	require.Len(t, unnamed, 1)
	assert.Empty(t, unnamed[0].EnvName, "a secret without an env name scans as empty")
}

func TestRekeyReplacesEnvelopesAndRecipient(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("re/key", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion("re/key", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.NoError(t, testVault.Disable("re/key", 1))

	_, err = testVault.AppendVersion("destroyed/one", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.Purge("destroyed/one")
	require.NoError(t, err)

	count, err := testVault.Rekey("age1new-fake-recipient", func(_ string, _ int64, envelope []byte) ([]byte, error) {
		return append([]byte("rekeyed:"), envelope...), nil
	})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "enabled and disabled versions rekey, destroyed do not")

	recipient, err := testVault.Recipient()
	require.NoError(t, err)
	assert.Equal(t, "age1new-fake-recipient", recipient)

	newest, err := testVault.NewestEnabled("re/key")
	require.NoError(t, err)
	assert.Contains(t, string(newest.Envelope), "rekeyed:")
}

func TestRekeyFailureRollsBackEverything(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion("roll/back", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	beforeNewest, err := testVault.NewestEnabled("roll/back")
	require.NoError(t, err)

	_, err = testVault.Rekey("age1never-stored", func(string, int64, []byte) ([]byte, error) {
		return nil, assert.AnError
	})
	require.Error(t, err)

	recipient, err := testVault.Recipient()
	require.NoError(t, err)
	assert.Equal(t, fakeRecipient, recipient, "recipient must not change on failed rekey")

	afterNewest, err := testVault.NewestEnabled("roll/back")
	require.NoError(t, err)
	assert.Equal(t, beforeNewest.Envelope, afterNewest.Envelope, "envelopes must not change on failed rekey")
}
