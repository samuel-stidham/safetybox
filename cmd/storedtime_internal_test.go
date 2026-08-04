package cmd

import (
	"testing"

	"github.com/samuel-stidham/safetybox/v4/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCorruptStoredTimeNamesTheSecretAndColumn pins GitHub issue #13. An
// expires_at column flipped to a non-NULL empty string aborted reads at
// the SQL scan layer with a bare "parse stored time" error. Nothing
// printed and no plaintext moved, so the behaviour was already
// fail-closed. The gap was the message: no secret name, no column, and
// no sign that the vault had been edited.
//
// The whole-batch failure is deliberate and stays. Softening it to a
// per-secret skip would hide real corruption.
func TestCorruptStoredTimeNamesTheSecretAndColumn(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		stored  string
		wantCol string
	}{
		{name: "empty string", stored: "", wantCol: "expires_at"},
		{name: "arbitrary text", stored: "not-a-time", wantCol: "expires_at"},
		{name: "date without time", stored: "2099-01-01", wantCol: "expires_at"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newCLIFixture(t)

			fixture.runOK("fake-value\n", "set", "api/broken", "--env-name", "FAKE_BROKEN")

			tamperColumn(t, fixture.vaultPath, "expires_at", testCase.stored, "api/broken")

			_, _, err := fixture.run("", "get", "api/broken")

			require.Error(t, err, "a corrupt timestamp must fail the read")

			message := err.Error()
			assert.Contains(t, message, "api/broken", "the error must name the secret")
			assert.Contains(t, message, testCase.wantCol, "the error must name the column")
			assert.Contains(t, message, "stored timestamp is not valid",
				"the error must frame this as corruption, not a bare parse failure")
			assert.Contains(t, message, "edited outside safetybox",
				"the hint must say what happened")
			require.ErrorIs(t, err, vault.ErrStoredTimeCorrupt)
		})
	}
}

// TestCorruptStoredTimeFailsBatchVerbsLoudly keeps the corruption
// contract explicit. exec and a filtered reveal must fail whole rather
// than skipping the one secret, because a bad column is corruption and
// not the benign metadata drift the skip path exists for.
func TestCorruptStoredTimeFailsBatchVerbsLoudly(t *testing.T) {
	for _, verb := range [][]string{
		{"exec", "--", "true"},
		{"reveal", "--env", "--format", "sh"},
		{"list"},
	} {
		t.Run(verb[0], func(t *testing.T) {
			fixture := newCLIFixture(t)

			fixture.runOK("fake-healthy\n", "set", "api/healthy", "--env-name", "FAKE_HEALTHY")
			fixture.runOK("fake-broken\n", "set", "api/broken", "--env-name", "FAKE_BROKEN")

			tamperColumn(t, fixture.vaultPath, "expires_at", "", "api/broken")

			stdout, _, err := fixture.run("", verb...)

			require.Error(t, err, "%v must fail loudly on a corrupt timestamp", verb)
			require.ErrorIs(t, err, vault.ErrStoredTimeCorrupt)
			assert.Contains(t, err.Error(), "api/broken")
			assert.NotContains(t, stdout, "fake-healthy",
				"corruption must deny the batch rather than deliver part of it")
			assert.NotContains(t, stdout, "fake-broken")
		})
	}
}

// TestValidExpiryStillParses guards against the stricter framing
// rejecting timestamps safetybox itself writes.
func TestValidExpiryStillParses(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-value\n", "set", "api/ok", "--expires", "2099-01-01")

	stdout, _ := fixture.runOK("", "show", "api/ok")
	assert.Contains(t, stdout, "2099-01-01")

	// A cleared expiry stores NULL, which is absent rather than corrupt.
	fixture.runOK("fake-value\n", "set", "api/ok", "--expires", "")
	fixture.runOK("", "show", "api/ok")
}
