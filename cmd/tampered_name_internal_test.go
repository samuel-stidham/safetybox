package cmd

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The tampered name forges a log record with its newline and carries a
// live erase-line escape sequence.
const (
	fakeForgedName        = "api/a\nINFO fake forged line\x1b[2K"
	fakeForgedNameEscaped = `"api/a\nINFO fake forged line\x1b[2K"`
)

// tamperName rewrites a secret's name directly, standing in for someone
// with write access to the vault file. The name grammar is enforced on
// write, so no safetybox verb can store this name.
func tamperName(t *testing.T, vaultPath, from, to string) {
	t.Helper()

	handle, err := sql.Open("sqlite", "file:"+vaultPath)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	_, err = handle.ExecContext(t.Context(), "UPDATE secret SET name = ? WHERE name = ?", to, from)
	require.NoError(t, err)
}

// assertNameCannotForgeALogLine checks the error names the tampered
// secret quoted and escaped, on one line, with no live control byte.
func assertNameCannotForgeALogLine(t *testing.T, err error) {
	t.Helper()

	require.Error(t, err)
	require.ErrorContains(t, err, "reseal "+fakeForgedNameEscaped+" version 1: ")
	assert.NotContains(t, err.Error(), "\n", "a tampered name must not start a new log line")
	assert.NotContains(t, err.Error(), "\x1b", "a tampered name must not reach the terminal as an escape sequence")
}

// TestRekeyEscapesATamperedName pins that rekey quotes a name the
// grammar does not allow. The envelope is sealed to the original name, so
// the reseal fails and the error names the row.
func TestRekeyEscapesATamperedName(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/a")

	tamperName(t, fixture.vaultPath, "api/a", fakeForgedName)

	_, _, err := fixture.run("", "rekey")

	assertNameCannotForgeALogLine(t, err)
}

// TestMigrateEscapesATamperedName is the same check on the migrate path.
func TestMigrateEscapesATamperedName(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/a")

	downgradeToV1(t, fixture)
	tamperName(t, fixture.vaultPath, "api/a", fakeForgedName)

	_, _, err := fixture.run("", "migrate")

	assertNameCannotForgeALogLine(t, err)
}

// TestResealErrorKeepsAValidNameUnquoted guards the other direction. A
// name the grammar allows must print exactly as it did before.
func TestResealErrorKeepsAValidNameUnquoted(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/a")

	// A valid name the envelope was not sealed to still fails the reseal.
	tamperName(t, fixture.vaultPath, "api/a", "api/b")

	_, _, err := fixture.run("", "rekey")

	require.Error(t, err)
	assert.ErrorContains(t, err, "reseal api/b version 1: ")
}
