package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecClearsASkippedVariableSoNoStaleValueSurvives pins the fix for
// the fail-open skip. A batch verb skips a secret whose metadata no
// longer matches the sealed value, which the docs called fail-safe. On
// its own it was not: buildSecretEnv starts from os.Environ, so a
// variable the parent already held stayed visible to the child, and the
// child could not tell it from the real secret. The run exited 0.
func TestExecClearsASkippedVariableSoNoStaleValueSurvives(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-real-value\n", "set", "api/tampered", "--env-name", "FAKE_TAMPERED")
	fixture.runOK("fake-healthy-value\n", "set", "api/healthy", "--env-name", "FAKE_HEALTHY")

	// A stale value already in the environment is what the child would
	// otherwise read instead of the secret safetybox declined to deliver.
	t.Setenv("FAKE_TAMPERED", "stale-attacker-controlled-value")

	tamperColumn(t, fixture.vaultPath, "expires_at", "2099-01-01T00:00:00Z", "api/tampered")

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c",
		`printf 'tampered=[%s] healthy=[%s]' "$FAKE_TAMPERED" "$FAKE_HEALTHY"`)

	assert.Equal(t, "tampered=[] healthy=[fake-healthy-value]", stdout,
		"a skipped secret must leave its variable absent, never stale")
	assert.NotContains(t, stdout, "stale-attacker-controlled-value",
		"the child must not read the value the parent happened to hold")
	assert.Contains(t, stderr, "skipped")
	assert.Contains(t, stderr, "cleared from the environment")
}

// TestExecKeepsAnEnvNameAnotherSecretSupplies guards against clearing
// too much. When one secret is skipped but another legitimately supplies
// the same env name, that value is current and must survive.
func TestExecKeepsAnEnvNameAnotherSecretSupplies(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-good-value\n", "set", "api/aaa-good", "--env-name", "FAKE_SHARED")
	fixture.runOK("fake-other-value\n", "set", "api/zzz-tampered", "--env-name", "FAKE_SHARED")

	tamperColumn(t, fixture.vaultPath, "expires_at", "2099-01-01T00:00:00Z", "api/zzz-tampered")

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_SHARED"`)

	assert.Equal(t, "fake-good-value", stdout,
		"a name another secret still supplies must not be cleared")
	assert.Contains(t, stderr, "skipped")
	assert.NotContains(t, stderr, "cleared from the environment")
}

// TestRevealEmitsAnEraseLineForASkippedSecret covers the other consumer.
// A shell that sources reveal's output keeps whatever it already held
// under a name reveal omitted, so omitting the assignment is not enough.
func TestRevealEmitsAnEraseLineForASkippedSecret(t *testing.T) {
	for _, testCase := range []struct {
		format string
		erase  string
	}{
		{format: "sh", erase: "unset FAKE_TAMPERED"},
		{format: "fish", erase: "set --erase FAKE_TAMPERED"},
	} {
		t.Run(testCase.format, func(t *testing.T) {
			fixture := newCLIFixture(t)

			fixture.runOK("fake-real-value\n", "set", "api/tampered", "--env-name", "FAKE_TAMPERED")
			fixture.runOK("fake-healthy-value\n", "set", "api/healthy", "--env-name", "FAKE_HEALTHY")

			tamperColumn(t, fixture.vaultPath, "expires_at", "2099-01-01T00:00:00Z", "api/tampered")

			stdout, stderr := fixture.runOK("", "reveal", "--env", "--format", testCase.format)

			assert.Contains(t, stdout, testCase.erase,
				"a skipped secret must erase its variable, not leave the shell's own value")
			assert.Contains(t, stdout, "FAKE_HEALTHY",
				"an unrelated secret must still be delivered")
			assert.NotContains(t, stdout, "fake-real-value",
				"the withheld value must never be emitted")
			assert.Contains(t, stderr, "erased")

			// The erase must come after the assignments, so a name another
			// secret supplied is not removed by ordering alone.
			assert.Greater(t, strings.Index(stdout, testCase.erase),
				strings.Index(stdout, "FAKE_HEALTHY"),
				"erase lines belong after the assignments")
		})
	}
}

// TestRevealKeepsAnEnvNameAnotherSecretSupplies mirrors the exec guard
// for the shell formats.
func TestRevealKeepsAnEnvNameAnotherSecretSupplies(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-good-value\n", "set", "api/aaa-good", "--env-name", "FAKE_SHARED")
	fixture.runOK("fake-other-value\n", "set", "api/zzz-tampered", "--env-name", "FAKE_SHARED")

	tamperColumn(t, fixture.vaultPath, "expires_at", "2099-01-01T00:00:00Z", "api/zzz-tampered")

	stdout, _ := fixture.runOK("", "reveal", "--env", "--format", "sh")

	assert.NotContains(t, stdout, "unset FAKE_SHARED",
		"a name another secret still supplies must not be erased")
	assert.Contains(t, stdout, "fake-good-value")
}

// TestExplicitRevealStillFailsLoudOnTamper guards the behaviour the skip
// path deliberately does not change. Naming a secret explicitly must
// still fail rather than quietly erase it.
func TestExplicitRevealStillFailsLoudOnTamper(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-real-value\n", "set", "api/tampered", "--env-name", "FAKE_TAMPERED")

	tamperColumn(t, fixture.vaultPath, "expires_at", "2099-01-01T00:00:00Z", "api/tampered")

	_, _, err := fixture.run("", "reveal", "api/tampered")

	require.Error(t, err, "an explicitly named secret must fail loud on a metadata mismatch")
	assert.NotContains(t, err.Error(), "fake-real-value")
}
