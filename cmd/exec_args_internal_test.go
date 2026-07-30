package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecDoesNotParseFlagsAfterTheCommand pins the fix for flag
// interspersion in exec. A flag placed after the child command used to
// bind to safetybox, so a trailing --vault redirected which vault was
// read and the child silently lost the argument. Any wrapper shaped
// like `safetybox exec cmd "$@"` handed that control to its caller.
//
// These invocations deliberately omit the `--` separator, because cobra
// already stops parsing flags there. Without it is where the bug lived.
func TestExecDoesNotParseFlagsAfterTheCommand(t *testing.T) {
	fixture := newCLIFixture(t)

	t.Run("a trailing vault flag reaches the child", func(t *testing.T) {
		stdout, stderr, err := fixture.run("",
			"exec", "sh", "-c", `printf '%s %s' "$1" "$2"`,
			"sh", "--vault", "/nonexistent/evil.db")

		// Had safetybox claimed the flag, it would have failed trying to
		// open a vault that does not exist.
		require.NoError(t, err, "stderr: %s", stderr)
		assert.Equal(t, "--vault /nonexistent/evil.db", stdout,
			"everything after the command name belongs to the child")
	})

	t.Run("a trailing identity flag reaches the child", func(t *testing.T) {
		stdout, stderr, err := fixture.run("",
			"exec", "sh", "-c", `printf '%s' "$1"`,
			"sh", "--identity", "/nonexistent/evil.age")

		require.NoError(t, err, "stderr: %s", stderr)
		assert.Equal(t, "--identity", stdout)
	})

	t.Run("a trailing help flag reaches the child", func(t *testing.T) {
		stdout, stderr, err := fixture.run("",
			"exec", "sh", "-c", `printf '%s' "$1"`, "sh", "--help")

		require.NoError(t, err, "stderr: %s", stderr)
		assert.Equal(t, "--help", stdout,
			"exec must run the child, not print its own help")
	})

	t.Run("a trailing verbose shorthand reaches the child", func(t *testing.T) {
		stdout, stderr, err := fixture.run("",
			"exec", "sh", "-c", `printf '%s' "$1"`, "sh", "-v")

		require.NoError(t, err, "stderr: %s", stderr)
		assert.Equal(t, "-v", stdout)
	})
}

// TestExecStillAcceptsItsOwnFlagsBeforeTheCommand guards the other side
// of the change. safetybox's flags must keep working when they appear
// where they belong, and the `--` form must keep working too.
func TestExecStillAcceptsItsOwnFlagsBeforeTheCommand(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-value\n", "set", testSecretName, "--env-name", "FAKE_TEST_KEY")

	t.Run("with an explicit separator", func(t *testing.T) {
		stdout, _ := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_TEST_KEY"`)
		assert.Equal(t, "fake-value", stdout)
	})

	t.Run("without an explicit separator", func(t *testing.T) {
		stdout, _ := fixture.runOK("", "exec", "sh", "-c", `printf '%s' "$FAKE_TEST_KEY"`)
		assert.Equal(t, "fake-value", stdout)
	})
}
