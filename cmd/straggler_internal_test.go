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

// strandLegacyEnvelope rewrites one secret's newest version back into the
// version 1 frame while the vault stays at the current format.
//
// That is exactly what a 2.x binary leaves behind when it races migrate.
// The old binary checks the format only when it opens the vault and takes
// no part in the migrate lock, so a set that began during the migration
// commits an old frame the moment migrate's transaction lands.
func strandLegacyEnvelope(t *testing.T, fixture *cliFixture, name string) {
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

	value, _, err := envelope.Open(key, address, blob)
	require.NoError(t, err)

	legacy := sealLegacyForTest(t, key.Recipient(), address, value.Expose())
	value.Destroy()

	_, err = handle.ExecContext(ctx,
		"UPDATE secret_version SET envelope = ? WHERE id = ?", legacy, versionID)
	require.NoError(t, err)
}

// TestStrandedLegacyEnvelopeReadHintsAtMigrate pins the first half of
// GitHub issue #10. A stranded version 1 row used to fail every read with
// a bare tamper-shaped error, which told the operator nothing about an
// innocent race and pointed at no recovery.
func TestStrandedLegacyEnvelopeReadHintsAtMigrate(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-stranded-value\n", "set", "api/stranded")

	strandLegacyEnvelope(t, fixture, "api/stranded")

	_, _, err := fixture.run("", "get", "api/stranded")

	require.Error(t, err)
	require.ErrorIs(t, err, envelope.ErrLegacyEnvelope)
	assert.Contains(t, err.Error(), "safetybox migrate",
		"the error must point at the command that repairs it")
	assert.Contains(t, err.Error(), "older safetybox",
		"the error must name the likely cause instead of implying tampering")
	assert.NotContains(t, err.Error(), "fake-stranded-value")
}

// TestMigrateRepairsAStrandedLegacyEnvelope pins the second half. migrate
// used to refuse an already-current vault with ErrAlreadyCurrentFormat,
// so no tool repaired the row and the only recovery was re-setting the
// secret by hand.
func TestMigrateRepairsAStrandedLegacyEnvelope(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-stranded-value\n", "set", "api/stranded")
	fixture.runOK("fake-healthy-value\n", "set", "api/healthy")

	strandLegacyEnvelope(t, fixture, "api/stranded")

	// The row is unreadable before the repair.
	_, _, err := fixture.run("", "get", "api/stranded")
	require.Error(t, err)

	stdout, stderr := fixture.runOK("", "migrate")
	assert.Contains(t, stderr, "repaired")
	assert.Contains(t, stdout, `"migratedVersions": 1`)
	assert.Contains(t, stdout, `"result": "repaired"`)

	// The original value is readable again, and never had to be retyped.
	after, _ := fixture.runOK("", "reveal", "api/stranded")
	assert.Contains(t, after, "fake-stranded-value")

	// The healthy secret is untouched.
	healthy, _ := fixture.runOK("", "reveal", "api/healthy")
	assert.Contains(t, healthy, "fake-healthy-value")
}

// TestMigrateOnAHealthyVaultStillReportsNothingToDo guards the ordinary
// case. The repair pass decrypts every envelope to look for stragglers,
// and when it finds none the vault must be left exactly as it was.
func TestMigrateOnAHealthyVaultStillReportsNothingToDo(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-value-one\n", "set", "api/one")
	fixture.runOK("fake-value-two\n", "set", "api/two")

	before := readVaultBytes(t, fixture.vaultPath)

	stdout, stderr := fixture.runOK("", "migrate")

	assert.Contains(t, stderr, "already at the current format")
	assert.Empty(t, stdout, "a no-op migrate emits no JSON")

	assert.Equal(t, before, readVaultBytes(t, fixture.vaultPath),
		"a healthy vault must not be rewritten by the repair scan")

	value, _ := fixture.runOK("", "reveal", "api/one")
	assert.Contains(t, value, "fake-value-one")
}

// TestMigrateDoesNotRepairARealTamper keeps the repair narrow. Only a
// genuine version 1 frame is re-sealed. A corrupt or forged envelope must
// keep failing loudly rather than be quietly rewritten.
func TestMigrateDoesNotRepairARealTamper(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-value\n", "set", "api/corrupt")

	handle, err := sql.Open("sqlite", "file:"+fixture.vaultPath)
	require.NoError(t, err)

	_, err = handle.ExecContext(t.Context(),
		"UPDATE secret_version SET envelope = ? WHERE id = 1", []byte("not-an-envelope-at-all"))
	require.NoError(t, err)
	require.NoError(t, handle.Close())

	_, _, err = fixture.run("", "migrate")

	require.Error(t, err, "corruption must not be silently rewritten")
	require.NotErrorIs(t, err, vault.ErrEnvelopeCurrent)
	assert.Equal(t, 1, strings.Count(err.Error(), "the identity may not match this vault"),
		"the advice must print once, not once per layer: %v", err)
}

// TestMigrateHintsOnceOnACorruptLegacyEnvelope covers the same advice on
// the format upgrade path. The resealer and runMigrate both ask for
// the hint, and a corrupt envelope used to print it twice.
func TestMigrateHintsOnceOnACorruptLegacyEnvelope(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK("fake-value\n", "set", "api/corrupt")

	downgradeToV1(t, fixture)

	handle, err := sql.Open("sqlite", "file:"+fixture.vaultPath)
	require.NoError(t, err)

	_, err = handle.ExecContext(t.Context(),
		"UPDATE secret_version SET envelope = ? WHERE id = 1", []byte("not-an-envelope-at-all"))
	require.NoError(t, err)
	require.NoError(t, handle.Close())

	_, _, err = fixture.run("", "migrate")

	require.ErrorIs(t, err, envelope.ErrDecryptFailed)
	assert.Equal(t, 1, strings.Count(err.Error(), "the identity may not match this vault"),
		"the advice must print once, not once per layer: %v", err)
}

// readVaultBytes returns the vault file's contents, for proving a run
// left it untouched.
func readVaultBytes(t *testing.T, path string) []byte {
	t.Helper()

	contents, err := os.ReadFile(path)
	require.NoError(t, err)

	return contents
}
