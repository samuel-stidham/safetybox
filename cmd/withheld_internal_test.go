package cmd

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fakeStaleValue = "fake-stale-value-not-real"
	// printNulOrAbsent prints FAKE_NUL, or "absent" when it is unset, so
	// a cleared variable is told apart from an empty one.
	printNulOrAbsent = `printf '%s' "${FAKE_NUL-absent}"`
)

// TestExecClearsAVariableWithheldForItsValue pins that a secret exec
// skips for its value does not leave a stale value behind. exec cleared
// the variable when it skipped a secret for a metadata mismatch, and this
// skip path was left out. The child read the value the calling shell
// held and could not tell it from the secret.
func TestExecClearsAVariableWithheldForItsValue(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake\x00nul\n", "set", "api/nul", "--env-name", "FAKE_NUL")

	t.Setenv("FAKE_NUL", fakeStaleValue)

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", printNulOrAbsent)

	assert.Equal(t, "absent", stdout, "a withheld secret must leave its variable absent, never stale")
	assert.Contains(t, stderr, "secret skipped")
	assert.Contains(t, stderr, "variable cleared from the environment, so the child cannot read a stale value")
}

// TestExecWithheldSecretIsQuietInACleanEnvironment pins that the clearing
// warns only when this process held the variable. With nothing to clear,
// the skip warning is the only record.
func TestExecWithheldSecretIsQuietInACleanEnvironment(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake\x00nul\n", "set", "api/nul", "--env-name", "FAKE_NUL")

	require.NoError(t, os.Unsetenv("FAKE_NUL"))

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", printNulOrAbsent)

	assert.Equal(t, "absent", stdout)
	assert.Contains(t, stderr, "secret skipped")
	assert.NotContains(t, stderr, "cleared from the environment")
}

// TestExecKeepsAWithheldEnvNameAnotherSecretSupplies guards against
// clearing too much. A name another secret delivers is current.
func TestExecKeepsAWithheldEnvNameAnotherSecretSupplies(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-good-value\n", "set", "api/aaa-good", "--env-name", "FAKE_NUL")
	fixture.runOK("fake\x00nul\n", "set", "api/zzz-nul", "--env-name", "FAKE_NUL")

	t.Setenv("FAKE_NUL", fakeStaleValue)

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", printNulOrAbsent)

	assert.Equal(t, "fake-good-value", stdout)
	assert.NotContains(t, stderr, "cleared from the environment")
}

// TestExecKeepsAReservedVariableASkippedSecretNamed pins that a reserved
// name is never cleared. A secret must not supply PATH, and skipping one
// must not take the inherited PATH away from the child either.
func TestExecKeepsAReservedVariableASkippedSecretNamed(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-real-value\n", "set", "api/tampered", "--env-name", "FAKE_TAMPERED")

	// Editing the column without re-sealing makes this a mismatch skip.
	tamperColumn(t, fixture.vaultPath, "env_name", "PATH", "api/tampered")

	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "${PATH-absent}"`)

	assert.Equal(t, os.Getenv("PATH"), stdout, "the child must keep the PATH it inherited")
	assert.Contains(t, stderr, "skipped")
	assert.NotContains(t, stderr, "cleared from the environment")
}

// TestRevealErasesAVariableWithheldForItsValue covers the other consumer.
// A shell that sources the output keeps whatever it held under a name
// reveal left out, so the skip must write an erase line.
func TestRevealErasesAVariableWithheldForItsValue(t *testing.T) {
	for _, testCase := range []struct {
		format string
		erase  string
	}{
		{format: "sh", erase: "unset FAKE_NUL"},
		{format: "fish", erase: "set --erase FAKE_NUL"},
	} {
		t.Run(testCase.format, func(t *testing.T) {
			fixture := newCLIFixture(t)

			fixture.runOK("fake\x00nul\n", "set", "api/nul", "--env-name", "FAKE_NUL")
			fixture.runOK("fake-healthy-value\n", "set", "api/healthy", "--env-name", "FAKE_HEALTHY")

			stdout, stderr := fixture.runOK("", "reveal", "--env", "--format", testCase.format)

			assert.Contains(t, stdout, testCase.erase+"\n")
			assert.Contains(t, stdout, "FAKE_HEALTHY")
			assert.Contains(t, stderr, "secret skipped")
			assert.Contains(t, stderr, "erased")
		})
	}
}

// TestRevealNeverErasesAReservedVariable mirrors the exec guard. Erasing
// PATH in a sourcing shell would be as harmful as setting it.
func TestRevealNeverErasesAReservedVariable(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-real-value\n", "set", "api/tampered", "--env-name", "FAKE_TAMPERED")

	tamperColumn(t, fixture.vaultPath, "env_name", "PATH", "api/tampered")

	stdout, _ := fixture.runOK("", "reveal", "--env", "--format", "sh")

	assert.NotContains(t, stdout, "PATH")
}

// TestExecSkipsASecretTooLargeForAVariable pins the per-variable size
// limit. Linux refuses to start a program when one environment string is
// over 32 pages, so one oversized secret failed every exec, including
// commands that never read it. The largest value that fits still injects,
// and one more byte is skipped with a warning that names the secret.
func TestExecSkipsASecretTooLargeForAVariable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("only Linux limits the size of one environment string")
	}

	const envName = "FAKE_BIG"

	limit := maxEnvValueBytes(envName)

	t.Run("largest value that fits", func(t *testing.T) {
		fixture := newCLIFixture(t)

		fixture.runOK(strings.Repeat("f", limit)+"\n", "set", "api/big", "--env-name", envName)

		stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "${#FAKE_BIG}"`)

		assert.Equal(t, strconv.Itoa(limit), stdout, "the child must receive the whole value")
		assert.NotContains(t, stderr, "secret skipped")
	})

	t.Run("one byte over", func(t *testing.T) {
		fixture := newCLIFixture(t)

		fixture.runOK("fake-small\n", "set", "api/small", "--env-name", "FAKE_SMALL")
		fixture.runOK(strings.Repeat("f", limit+1)+"\n", "set", "api/big", "--env-name", envName)

		// A stale value under the withheld name must be cleared too.
		t.Setenv(envName, fakeStaleValue)

		stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c",
			`printf '%s %s' "$FAKE_SMALL" "${FAKE_BIG-absent}"`)

		assert.Equal(t, "fake-small absent", stdout, "the rest must inject, and the withheld name must be absent")
		assert.Contains(t, stderr, "api/big", "the skipped secret must be named")
		assert.Contains(t, stderr, "value is too large for an environment variable, which holds at most")
		assert.Contains(t, stderr, "bytes under this name")
		assert.Contains(t, stderr, "cleared from the environment")
	})
}
