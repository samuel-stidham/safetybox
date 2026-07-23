package vault_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/samuel-stidham/safetybox/v2/internal/vault"

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

	require.NoError(t, vault.Create(t.Context(), path, fakeRecipient))

	opened, err := vault.Open(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, opened.Close()) })

	return opened
}

func TestAppendVersionCreatesAndIncrements(t *testing.T) {
	testVault := openTestVault(t)

	first, err := testVault.AppendVersion(t.Context(), "api/testing/fake", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	assert.Equal(t, int64(1), first.Version.Number)
	assert.Equal(t, vault.StateEnabled, first.Version.State)

	second, err := testVault.AppendVersion(t.Context(), "api/testing/fake", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	assert.Equal(t, int64(2), second.Version.Number)
	assert.Zero(t, second.Revoked, "updates must not auto-disable prior versions")

	newest, err := testVault.NewestEnabled(t.Context(), "api/testing/fake")
	require.NoError(t, err)
	assert.Equal(t, "api/testing/fake", newest.Secret.Name)
	assert.Equal(t, int64(2), newest.Version.Number)
	assert.Equal(t, []byte("fake-envelope:api/v1/api/testing/fake/2"), newest.Envelope)
}

func TestAppendVersionRevokePrevious(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "rotate/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "rotate/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	third, err := testVault.AppendVersion(t.Context(), "rotate/me", vault.SetOptions{RevokePrevious: true}, fakeSealer(t))
	require.NoError(t, err)
	assert.Equal(t, int64(2), third.Revoked)

	_, versions, err := testVault.Meta(t.Context(), "rotate/me")
	require.NoError(t, err)
	require.Len(t, versions, 3)
	assert.Equal(t, vault.StateDisabled, versions[0].State)
	assert.Equal(t, vault.StateDisabled, versions[1].State)
	assert.Equal(t, vault.StateEnabled, versions[2].State)
}

func TestAppendVersionRejectsBadNames(t *testing.T) {
	testVault := openTestVault(t)

	for _, name := range []string{"", "/leading", "trailing/", "has space", "new\nline", "double//slash"} {
		_, err := testVault.AppendVersion(t.Context(), name, vault.SetOptions{}, fakeSealer(t))
		require.ErrorIs(t, err, vault.ErrInvalidName, "name %q must be rejected", name)
	}
}

func TestAppendVersionStoresAttributes(t *testing.T) {
	testVault := openTestVault(t)
	envName := "FAKE_TEST_KEY"
	expiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	result, err := testVault.AppendVersion(t.Context(), "api/testing/fake",
		vault.SetOptions{EnvName: &envName, ExpiresAt: &expiry}, fakeSealer(t))
	require.NoError(t, err)
	require.NotNil(t, result.Secret.EnvName)
	assert.Equal(t, envName, *result.Secret.EnvName)
	require.NotNil(t, result.Secret.ExpiresAt)
	assert.True(t, expiry.Equal(*result.Secret.ExpiresAt))

	// A later set without attributes keeps them.
	kept, err := testVault.AppendVersion(t.Context(), "api/testing/fake", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	require.NotNil(t, kept.Secret.EnvName)
	assert.Equal(t, envName, *kept.Secret.EnvName)
	require.NotNil(t, kept.Secret.ExpiresAt)
}

func TestNewestEnabledSkipsDisabled(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "skip/disabled", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "skip/disabled", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.NoError(t, testVault.Disable(t.Context(), "skip/disabled", 2))

	newest, err := testVault.NewestEnabled(t.Context(), "skip/disabled")
	require.NoError(t, err)
	assert.Equal(t, int64(1), newest.Version.Number)

	require.NoError(t, testVault.Disable(t.Context(), "skip/disabled", 1))

	_, err = testVault.NewestEnabled(t.Context(), "skip/disabled")
	require.ErrorIs(t, err, vault.ErrVersionNotFound)
}

func TestNewestEnabledErrors(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.NewestEnabled(t.Context(), "missing/secret")
	require.ErrorIs(t, err, vault.ErrSecretNotFound)

	_, err = testVault.AppendVersion(t.Context(), "deleted/secret", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	require.NoError(t, testVault.SoftDelete(t.Context(), "deleted/secret"))

	_, err = testVault.NewestEnabled(t.Context(), "deleted/secret")
	require.ErrorIs(t, err, vault.ErrSecretDeleted)
}

func TestSetRevivesSoftDeletedSecret(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "revive/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	require.NoError(t, testVault.SoftDelete(t.Context(), "revive/me"))

	revived, err := testVault.AppendVersion(t.Context(), "revive/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)
	assert.Nil(t, revived.Secret.DeletedAt)
	assert.Equal(t, int64(2), revived.Version.Number, "version numbers survive delete and revive")
}

func TestListAndPrefix(t *testing.T) {
	testVault := openTestVault(t)

	for _, name := range []string{"api/stripe/live", "api/stripe/test", "db/postgres"} {
		_, err := testVault.AppendVersion(t.Context(), name, vault.SetOptions{}, fakeSealer(t))
		require.NoError(t, err)
	}

	require.NoError(t, testVault.SoftDelete(t.Context(), "db/postgres"))

	all, err := testVault.List(t.Context(), "")
	require.NoError(t, err)
	require.Len(t, all, 2, "deleted secrets stay out of list")

	stripe, err := testVault.List(t.Context(), "api/stripe/")
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

	_, err := testVault.AppendVersion(t.Context(), "expired/secret", vault.SetOptions{ExpiresAt: &past}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "fresh/secret", vault.SetOptions{ExpiresAt: &future}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "eternal/secret", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	stale, err := testVault.Stale(t.Context(), now)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, "expired/secret", stale[0].Name)
	assert.True(t, stale[0].Expired(now))

	// Expired secrets still resolve. Expiry is staleness, never
	// deletion.
	newest, err := testVault.NewestEnabled(t.Context(), "expired/secret")
	require.NoError(t, err)
	assert.NotEmpty(t, newest.Envelope)
}

func TestDisableErrors(t *testing.T) {
	testVault := openTestVault(t)

	require.ErrorIs(t, testVault.Disable(t.Context(), "missing", 1), vault.ErrSecretNotFound)

	_, err := testVault.AppendVersion(t.Context(), "dis/able", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.ErrorIs(t, testVault.Disable(t.Context(), "dis/able", 9), vault.ErrVersionNotFound)

	_, err = testVault.Purge(t.Context(), "dis/able")
	require.NoError(t, err)

	require.ErrorIs(t, testVault.Disable(t.Context(), "dis/able", 1), vault.ErrVersionDestroyed)
}

func TestSoftDeleteTwiceFails(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "del/ete", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.NoError(t, testVault.SoftDelete(t.Context(), "del/ete"))
	require.ErrorIs(t, testVault.SoftDelete(t.Context(), "del/ete"), vault.ErrSecretDeleted)
}

// TestSoftDeleteConcurrentKeepsOneTombstone covers B-9: the guarded
// update makes exactly one racing delete win, so a second delete or a
// purge cannot overwrite the first tombstone's timestamp. Without the
// AND deleted_at IS NULL guard, interleaved deletes both report success.
func TestSoftDeleteConcurrentKeepsOneTombstone(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "race/delete", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	const workers = 8

	var waitGroup sync.WaitGroup

	results := make([]error, workers)

	waitGroup.Add(workers)

	for i := range workers {
		go func(index int) {
			defer waitGroup.Done()

			results[index] = testVault.SoftDelete(t.Context(), "race/delete")
		}(i)
	}

	waitGroup.Wait()

	var succeeded, alreadyDeleted int

	for _, result := range results {
		switch {
		case result == nil:
			succeeded++
		case errors.Is(result, vault.ErrSecretDeleted):
			alreadyDeleted++
		default:
			t.Fatalf("unexpected delete error: %v", result)
		}
	}

	assert.Equal(t, 1, succeeded, "exactly one concurrent delete must win")
	assert.Equal(t, workers-1, alreadyDeleted, "the rest must report already deleted")
}

func TestPurgeDestroysEnvelopes(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "purge/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "purge/me", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	destroyed, err := testVault.Purge(t.Context(), "purge/me")
	require.NoError(t, err)
	assert.Equal(t, int64(2), destroyed)

	meta, versions, err := testVault.Meta(t.Context(), "purge/me")
	require.NoError(t, err)
	assert.NotNil(t, meta.DeletedAt, "purge implies delete")

	for _, version := range versions {
		assert.Equal(t, vault.StateDestroyed, version.State)
	}

	_, err = testVault.NewestEnabled(t.Context(), "purge/me")
	require.ErrorIs(t, err, vault.ErrSecretDeleted)
}

func TestEntries(t *testing.T) {
	testVault := openTestVault(t)
	envName := "FAKE_STRIPE_KEY"

	_, err := testVault.AppendVersion(t.Context(), "api/stripe/live", vault.SetOptions{EnvName: &envName}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "api/stripe/live", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "db/postgres", vault.SetOptions{}, fakeSealer(t))
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
			entries, err := testVault.Entries(t.Context(), testCase.filter)
			require.NoError(t, err)
			require.Len(t, entries, len(testCase.want))

			for index, entry := range entries {
				assert.Equal(t, testCase.want[index], entry.Name)
			}
		})
	}

	entries, err := testVault.Entries(t.Context(), vault.EntryFilter{EnvNamed: true})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, envName, entries[0].EnvName)
	assert.Equal(t, int64(2), entries[0].Version, "entries resolve the newest enabled version")

	unnamed, err := testVault.Entries(t.Context(), vault.EntryFilter{Prefix: "db/"})
	require.NoError(t, err)
	require.Len(t, unnamed, 1)
	assert.Empty(t, unnamed[0].EnvName, "a secret without an env name scans as empty")
}

// TestEntriesPrefixIsExactNotLike proves the prefix filter does not
// treat name characters as LIKE wildcards or fold ASCII case, so
// reveal --prefix cannot over-match and disclose unselected secrets.
func TestEntriesPrefixIsExactNotLike(t *testing.T) {
	testVault := openTestVault(t)

	for _, name := range []string{"api/my_service", "api/myXservice", "prod/db", "api/my_service/child"} {
		_, err := testVault.AppendVersion(t.Context(), name, vault.SetOptions{}, fakeSealer(t))
		require.NoError(t, err)
	}

	// `_` must be literal, not a single-char wildcard.
	got, err := testVault.Entries(t.Context(), vault.EntryFilter{Prefix: "api/my_service"})
	require.NoError(t, err)

	names := make([]string, 0, len(got))
	for _, entry := range got {
		names = append(names, entry.Name)
	}

	assert.ElementsMatch(t, []string{"api/my_service", "api/my_service/child"}, names,
		"prefix must match literally, never treat _ as a wildcard")
	assert.NotContains(t, names, "api/myXservice", "_ must not match an arbitrary character")

	// Case sensitivity: Prod/ must not match prod/.
	upper, err := testVault.Entries(t.Context(), vault.EntryFilter{Prefix: "Prod/"})
	require.NoError(t, err)
	assert.Empty(t, upper, "prefix match must be case-sensitive")

	// A wildcard character in the prefix matches nothing literal.
	wildcard, err := testVault.Entries(t.Context(), vault.EntryFilter{Prefix: "%"})
	require.NoError(t, err)
	assert.Empty(t, wildcard, "a literal % prefix must not match every row")
}

func TestRekeyReplacesEnvelopesAndRecipient(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "re/key", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "re/key", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	require.NoError(t, testVault.Disable(t.Context(), "re/key", 1))

	_, err = testVault.AppendVersion(t.Context(), "destroyed/one", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.Purge(t.Context(), "destroyed/one")
	require.NoError(t, err)

	count, err := testVault.Rekey(t.Context(), "age1new-fake-recipient",
		func(_ string, _ int64, envelope []byte) ([]byte, error) {
			return append([]byte("rekeyed:"), envelope...), nil
		})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "enabled and disabled versions rekey, destroyed do not")

	recipient, err := testVault.Recipient(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "age1new-fake-recipient", recipient)

	newest, err := testVault.NewestEnabled(t.Context(), "re/key")
	require.NoError(t, err)
	assert.Contains(t, string(newest.Envelope), "rekeyed:")
}

func TestRekeyFailureRollsBackEverything(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "roll/back", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	beforeNewest, err := testVault.NewestEnabled(t.Context(), "roll/back")
	require.NoError(t, err)

	_, err = testVault.Rekey(t.Context(), "age1never-stored", func(string, int64, []byte) ([]byte, error) {
		return nil, assert.AnError
	})
	require.Error(t, err)

	recipient, err := testVault.Recipient(t.Context())
	require.NoError(t, err)
	assert.Equal(t, fakeRecipient, recipient, "recipient must not change on failed rekey")

	afterNewest, err := testVault.NewestEnabled(t.Context(), "roll/back")
	require.NoError(t, err)
	assert.Equal(t, beforeNewest.Envelope, afterNewest.Envelope, "envelopes must not change on failed rekey")
}

// TestRekeyResealsEachVersionFromItsOwnEnvelope pins that rekey passes
// each version its own envelope. Rekey now fetches envelopes one row at
// a time instead of collecting them all, so a mixed-up fetch would
// reseal a secret from another secret's bytes. Each fake envelope
// embeds its address, so a swap would show up as the wrong address.
func TestRekeyResealsEachVersionFromItsOwnEnvelope(t *testing.T) {
	testVault := openTestVault(t)

	_, err := testVault.AppendVersion(t.Context(), "alpha/one", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.AppendVersion(t.Context(), "beta/two", vault.SetOptions{}, fakeSealer(t))
	require.NoError(t, err)

	_, err = testVault.Rekey(t.Context(), "age1new-fake-recipient",
		func(_ string, _ int64, envelope []byte) ([]byte, error) {
			return append([]byte("rekeyed:"), envelope...), nil
		})
	require.NoError(t, err)

	alpha, err := testVault.NewestEnabled(t.Context(), "alpha/one")
	require.NoError(t, err)
	assert.Contains(t, string(alpha.Envelope), vault.CanonicalAddress("alpha/one", 1),
		"alpha must be resealed from its own envelope")

	beta, err := testVault.NewestEnabled(t.Context(), "beta/two")
	require.NoError(t, err)
	assert.Contains(t, string(beta.Envelope), vault.CanonicalAddress("beta/two", 1),
		"beta must be resealed from its own envelope")
}

// TestEntriesPrefixStopsAtSegmentBoundary proves the prefix filter
// selects whole name segments, so a prefix never leaks a sibling
// hierarchy that merely shares leading characters.
func TestEntriesPrefixStopsAtSegmentBoundary(t *testing.T) {
	testVault := openTestVault(t)

	fixtures := []string{
		"projects/myapp", "projects/myapp/token",
		"projects/myapp-legacy/db", "projects/myapplication/key",
	}

	for _, name := range fixtures {
		_, err := testVault.AppendVersion(t.Context(), name, vault.SetOptions{}, fakeSealer(t))
		require.NoError(t, err)
	}

	got, err := testVault.Entries(t.Context(), vault.EntryFilter{Prefix: "projects/myapp"})
	require.NoError(t, err)

	names := make([]string, 0, len(got))
	for _, entry := range got {
		names = append(names, entry.Name)
	}

	assert.ElementsMatch(t, []string{"projects/myapp", "projects/myapp/token"}, names,
		"a prefix must select the name itself and whole segments under it, never lexical siblings")

	// A trailing slash selects the same set.
	slashed, err := testVault.Entries(t.Context(), vault.EntryFilter{Prefix: "projects/myapp/"})
	require.NoError(t, err)
	require.Len(t, slashed, 2)

	// List applies the same rule.
	summaries, err := testVault.List(t.Context(), "projects/myapp")
	require.NoError(t, err)
	require.Len(t, summaries, 2)
}
