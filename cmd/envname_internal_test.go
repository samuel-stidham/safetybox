package cmd

import (
	"bytes"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/samuel-stidham/safetybox/v4/internal/envelope"
	"github.com/samuel-stidham/safetybox/v4/internal/identity"
	"github.com/samuel-stidham/safetybox/v4/internal/vault"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestIsReservedEnvName pins which names a secret may not carry. Each
// one is a valid shell identifier, so isShellIdentifier accepts them and
// this is the only thing standing between a vault row and control of
// every exec child.
func TestIsReservedEnvName(t *testing.T) {
	for _, reserved := range []string{
		"PATH", "IFS", "ENV", "BASH_ENV", "SHELL", "PS4",
		"SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "PROMPT_COMMAND",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
	} {
		assert.True(t, isReservedEnvName(reserved), "%s must be reserved", reserved)
		assert.True(t, isShellIdentifier(reserved),
			"%s is a valid identifier, which is why the denylist is needed", reserved)
	}

	for _, allowed := range []string{
		"FAKE_API_KEY", "DATABASE_URL", "AWS_ACCESS_KEY_ID", "STRIPE_SECRET",
		// Environment variables are case-sensitive, so a lowercase
		// spelling is a different variable with none of the meaning.
		"path", "Ld_Preload", "ifs",
		// A name that merely mentions a reserved one is still data.
		"MY_PATH", "PATH_TO_CERT", "OLD_SHELL",
	} {
		assert.False(t, isReservedEnvName(allowed), "%s must be allowed", allowed)
	}
}

// TestSetRefusesReservedEnvName checks the gate where the message can
// reach the person typing the command.
func TestSetRefusesReservedEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	for _, reserved := range []string{"PATH", "LD_PRELOAD", "IFS", "DYLD_INSERT_LIBRARIES"} {
		t.Run(reserved, func(t *testing.T) {
			_, _, err := fixture.run("fake-value\n", "set", "evil/"+strings.ToLower(reserved),
				"--env-name", reserved)

			require.Error(t, err, "set must refuse to store %s as an env name", reserved)
			assert.Contains(t, err.Error(), "reserved")
		})
	}
}

// TestSetStillAcceptsOrdinaryEnvNames guards against the denylist
// growing teeth it should not have.
func TestSetStillAcceptsOrdinaryEnvNames(t *testing.T) {
	fixture := newCLIFixture(t)

	for _, allowed := range []string{"FAKE_API_KEY", "MY_PATH", "path"} {
		_, _, err := fixture.run("fake-value\n", "set", "ok/"+strings.ToLower(allowed),
			"--env-name", allowed)
		require.NoError(t, err, "%s is data and must be allowed", allowed)
	}
}

// forgeReservedEnvName rewrites one secret so its env name is reserved,
// sealing the envelope to match so the row passes the metadata binding.
// This is the attacker with vault write access but no passphrase:
// envelope.Seal needs only the recipient, which the vault stores in the
// clear. It is also what a row written by an older binary looks like.
func forgeReservedEnvName(t *testing.T, fixture *cliFixture, name, envName string) {
	t.Helper()

	passphrase, err := os.ReadFile(fixture.passphraseFile)
	require.NoError(t, err)

	key, cleanup, err := identity.Load(fixture.identityPath, bytes.TrimRight(passphrase, "\n"))
	require.NoError(t, err)

	defer cleanup()

	handle, err := sql.Open("sqlite", "file:"+fixture.vaultPath)
	require.NoError(t, err)

	defer func() { require.NoError(t, handle.Close()) }()

	ctx := t.Context()

	var (
		versionID int64
		number    int64
		blob      []byte
	)

	row := handle.QueryRowContext(ctx,
		`SELECT sv.id, sv.version_number, sv.envelope
		   FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
		  WHERE s.name = ? AND sv.state = 'enabled'
		  ORDER BY sv.version_number DESC LIMIT 1`, name)
	require.NoError(t, row.Scan(&versionID, &number, &blob))

	address := vault.CanonicalAddress(name, number)

	value, bound, err := envelope.Open(key, address, blob)
	require.NoError(t, err)

	defer value.Destroy()

	bound.EnvName = envName

	forged, err := envelope.Seal(key.Recipient(), address, bound, value)
	require.NoError(t, err)

	_, err = handle.ExecContext(ctx,
		"UPDATE secret_version SET envelope = ? WHERE id = ?", forged, versionID)
	require.NoError(t, err)

	_, err = handle.ExecContext(ctx,
		"UPDATE secret SET env_name = ? WHERE name = ?", envName, name)
	require.NoError(t, err)
}

// TestExecSkipsAForgedReservedEnvName is the one that matters. A row
// carrying PATH would otherwise replace the child's real PATH, because
// buildSecretEnv starts from os.Environ and appends, and os/exec keeps
// the later value on a duplicate.
//
// Skipping is the safe outcome rather than an error: the child keeps the
// PATH it inherited, so a forged row cannot deny the run either.
func TestExecSkipsAForgedReservedEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-real-value\n", "set", "api/legit", "--env-name", "FAKE_LEGIT")
	fixture.runOK("/tmp/attacker/bin\n", "set", "api/poison", "--env-name", "FAKE_POISON")

	forgeReservedEnvName(t, fixture, "api/poison", "PATH")

	// The forged row must survive the tamper check, or this would be
	// testing metadata binding instead of the denylist.
	stdout, stderr := fixture.runOK("", "exec", "--", "sh", "-c",
		`printf '%s|%s' "$PATH" "$FAKE_LEGIT"`)

	assert.NotEqual(t, "/tmp/attacker/bin", strings.Split(stdout, "|")[0],
		"the vault must not decide the child's PATH")
	assert.Contains(t, stdout, "fake-real-value",
		"an unrelated secret must still be delivered")
	assert.Contains(t, stderr, "reserved")
	assert.NotContains(t, stderr, "does not match the sealed value",
		"the forged row must pass the binding check, so this tests the denylist")
}

// TestRevealSkipsAForgedReservedEnvName covers the other injection
// point. A sourced .envrc or secrets.fish applies these assignments to
// the whole shell session, so an emitted PATH line is worse than an
// injected one.
func TestRevealSkipsAForgedReservedEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-real-value\n", "set", "api/legit", "--env-name", "FAKE_LEGIT")
	fixture.runOK("/tmp/attacker/evil.so\n", "set", "api/poison", "--env-name", "FAKE_POISON")

	forgeReservedEnvName(t, fixture, "api/poison", "LD_PRELOAD")

	stdout, stderr := fixture.runOK("", "reveal", "--env", "--format", "sh")

	assert.NotContains(t, stdout, "LD_PRELOAD",
		"no assignment may set a variable the loader reads")
	assert.NotContains(t, stdout, "/tmp/attacker/evil.so")
	assert.Contains(t, stdout, "FAKE_LEGIT", "an unrelated secret must still be emitted")
	assert.Contains(t, stderr, "reserved")
}
