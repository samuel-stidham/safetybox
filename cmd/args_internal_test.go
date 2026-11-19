package cmd

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/samuel-stidham/safetybox/v4/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStrayArg stands in for a value typed or pasted in the wrong place.
const fakeStrayArg = "FAKE-STRAY-ARG"

// TestUsageErrorsNeverRepeatAStrayArgument runs every verb with more
// arguments than it accepts and asserts the argument reaches neither log
// format. A stray argument is the usual way a secret lands on a command
// line, so the usage error must count it and never quote it.
//
// The verbs come from the command tree, so a verb added later is covered
// without touching this test. exec and reveal take any number of
// arguments, so they have no too-many case.
func TestUsageErrorsNeverRepeatAStrayArgument(t *testing.T) {
	unbounded := map[string]bool{"exec": true, "reveal": true}

	var covered int

	for _, verb := range newRootCmd("test").Commands() {
		if unbounded[verb.Name()] {
			continue
		}

		covered++

		t.Run(verb.Name(), func(t *testing.T) {
			tmp := t.TempDir()
			t.Setenv("HOME", tmp)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("XDG_DATA_HOME", "")
			t.Setenv(envVault, "")
			t.Setenv(envIdentity, "")

			root := newRootCmd("test")
			root.SetArgs([]string{verb.Name(), fakeStrayArg, fakeStrayArg, fakeStrayArg})

			var stdout, stderr bytes.Buffer

			root.SetOut(&stdout)
			root.SetErr(&stderr)

			err := root.Execute()

			require.Error(t, err)
			require.ErrorContains(t, err, "too many arguments: "+verb.Name()+" accepts ")
			assert.NotContains(t, stdout.String(), fakeStrayArg)
			assert.NotContains(t, stderr.String(), fakeStrayArg)

			// Execute logs the returned error, so render it the same way
			// in both formats.
			for _, logJSON := range []bool{false, true} {
				var logged bytes.Buffer

				logging.Setup(&logged, logging.Options{JSON: logJSON})
				slog.Error(err.Error())

				assert.NotEmpty(t, logged.String())
				assert.NotContains(t, logged.String(), fakeStrayArg)
			}
		})
	}

	assert.Positive(t, covered)
}

// TestUsageErrorWording pins the wording shared with sanctuary, the Rust
// port, so the two programs report a miscounted command line the same way.
func TestUsageErrorWording(t *testing.T) {
	for _, testCase := range []struct {
		args []string
		want string
	}{
		{args: []string{"rekey", fakeStrayArg}, want: "too many arguments: rekey accepts no arguments"},
		{args: []string{"set", "api/one", fakeStrayArg}, want: "too many arguments: set accepts 1 argument"},
		{args: []string{"disable", "api/one", "1", fakeStrayArg}, want: "too many arguments: disable accepts 2 arguments"},
		{args: []string{"list", "api", fakeStrayArg}, want: "too many arguments: list accepts at most 1 argument"},
		{args: []string{"get"}, want: "too few arguments: get accepts 1 argument"},
		{args: []string{"exec"}, want: "too few arguments: exec accepts at least 1 argument"},
	} {
		t.Run(testCase.want, func(t *testing.T) {
			root := newRootCmd("test")
			root.SetArgs(testCase.args)

			var stdout, stderr bytes.Buffer

			root.SetOut(&stdout)
			root.SetErr(&stderr)

			require.EqualError(t, root.Execute(), testCase.want)
		})
	}
}
