package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Obviously fake test material, never real secrets.
const (
	fakeValueOne   = "fake-value-one-not-real"
	fakeValueTwo   = "fake-value-two-not-real"
	fakeValueThree = "fake-value-three-not-real"
	testSecretName = "api/testing/fake"
)

// cliFixture is an initialized identity and vault in a temp dir.
type cliFixture struct {
	t              *testing.T
	identityPath   string
	vaultPath      string
	passphraseFile string
}

func newCLIFixture(t *testing.T) *cliFixture {
	t.Helper()

	tmp := t.TempDir()
	fixture := &cliFixture{
		t:              t,
		identityPath:   filepath.Join(tmp, "config", "identity.age"),
		vaultPath:      filepath.Join(tmp, "data", "vault.db"),
		passphraseFile: filepath.Join(tmp, "passphrase"),
	}

	require.NoError(t, os.WriteFile(fixture.passphraseFile, []byte(fakePassphrase+"\n"), 0o600))

	_, _, err := fixture.run("", initVerb)
	require.NoError(t, err)

	return fixture
}

// run invokes the CLI in process with the fixture's paths and
// passphrase file appended.
func (f *cliFixture) run(stdin string, args ...string) (string, string, error) {
	f.t.Helper()

	// Global flags go before the verb: anything after `--` belongs
	// to the exec child, never to safetybox.
	flagArgs := []string{
		"--identity", f.identityPath,
		"--vault", f.vaultPath,
		"--passphrase-file", f.passphraseFile,
	}

	full := make([]string, 0, len(flagArgs)+len(args))
	full = append(full, flagArgs...)
	full = append(full, args...)

	root := newRootCmd("test")
	root.SetArgs(full)

	var stdout, stderr bytes.Buffer

	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	err := root.Execute()

	return stdout.String(), stderr.String(), err
}

func (f *cliFixture) runOK(stdin string, args ...string) (string, string) {
	f.t.Helper()

	stdout, stderr, err := f.run(stdin, args...)
	require.NoError(f.t, err, "command %v failed, stderr: %s", args, stderr)

	return stdout, stderr
}

// decode parses a JSON object from a verb's stdout.
func decode(t *testing.T, raw string) map[string]any {
	t.Helper()

	var payload map[string]any

	require.NoError(t, json.Unmarshal([]byte(raw), &payload), "output was: %s", raw)

	return payload
}

func (f *cliFixture) revealValue(name string) string {
	f.t.Helper()

	stdout, _ := f.runOK("", "reveal", name)

	value, ok := decode(f.t, stdout)["value"].(string)
	require.True(f.t, ok, "reveal output missing value")

	return value
}

func TestRotationLifecycle(t *testing.T) {
	fixture := newCLIFixture(t)

	// Version 1 with an env name.
	stdout, _ := fixture.runOK(fakeValueOne+"\n", "set", testSecretName, "--env-name", "FAKE_TEST_KEY")
	assert.InDelta(t, 1, decode(t, stdout)["version"], 0)

	assert.Equal(t, fakeValueOne, fixture.revealValue(testSecretName))

	// Rotation appends. The old version stays enabled by design.
	stdout, _ = fixture.runOK(fakeValueTwo+"\n", "set", testSecretName)
	assert.InDelta(t, 2, decode(t, stdout)["version"], 0)
	assert.Equal(t, fakeValueTwo, fixture.revealValue(testSecretName))

	stdout, _ = fixture.runOK("", "show", testSecretName)
	versions, ok := decode(t, stdout)["versions"].([]any)
	require.True(t, ok)
	require.Len(t, versions, 2)

	for _, raw := range versions {
		version, castOK := raw.(map[string]any)
		require.True(t, castOK)
		assert.Equal(t, "enabled", version["state"], "rotation must not auto-disable")
	}

	// Disabling the newest version falls back to the previous one.
	fixture.runOK("", "disable", testSecretName, "2")
	assert.Equal(t, fakeValueOne, fixture.revealValue(testSecretName))

	// --revoke-previous disables everything older in one step.
	stdout, _ = fixture.runOK(fakeValueThree+"\n", "set", testSecretName, "--revoke-previous")
	payload := decode(t, stdout)
	assert.InDelta(t, 3, payload["version"], 0)
	assert.InDelta(t, 1, payload["revokedPrevious"], 0, "only version 1 was still enabled")
	assert.Equal(t, fakeValueThree, fixture.revealValue(testSecretName))
}

func TestGetRedactsValue(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", testSecretName)

	stdout, stderr := fixture.runOK("", "get", testSecretName)
	assert.Equal(t, "[REDACTED]", decode(t, stdout)["value"])
	assert.NotContains(t, stdout, fakeValueOne, "get must never print plaintext")
	assert.NotContains(t, stderr, fakeValueOne)
}

func TestListAndPrefixFiltering(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/stripe/live")
	fixture.runOK(fakeValueOne+"\n", "set", "db/postgres")

	stdout, _ := fixture.runOK("", "list", "--json")

	var all []map[string]any

	require.NoError(t, json.Unmarshal([]byte(stdout), &all))
	assert.Len(t, all, 2)

	stdout, _ = fixture.runOK("", "list", "api/", "--json")

	var filtered []map[string]any

	require.NoError(t, json.Unmarshal([]byte(stdout), &filtered))
	require.Len(t, filtered, 1)
	assert.Equal(t, "api/stripe/live", filtered[0]["name"])
}

func TestExecInjectsEnvironment(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", testSecretName, "--env-name", "FAKE_TEST_KEY")

	stdout, _ := fixture.runOK("", "exec", "--", "sh", "-c", `printf '%s' "$FAKE_TEST_KEY"`)
	assert.Equal(t, fakeValueOne, stdout)
}

func TestExecPropagatesExitCode(t *testing.T) {
	fixture := newCLIFixture(t)

	_, _, err := fixture.run("", "exec", "--", "sh", "-c", "exit 3")

	var exit exitCodeError

	require.ErrorAs(t, err, &exit)
	assert.Equal(t, 3, exit.code)
}

func TestExpiryIsStalenessNotDeletion(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "expired/secret", "--expires", "2020-01-02")

	stdout, _ := fixture.runOK("", "stale", "--json")

	var stale []map[string]any

	require.NoError(t, json.Unmarshal([]byte(stdout), &stale))
	require.Len(t, stale, 1)
	assert.Equal(t, "expired/secret", stale[0]["name"])

	// The expired secret warns on stderr and still resolves.
	_, stderr := fixture.runOK("", "get", "expired/secret")
	assert.Contains(t, stderr, "expired")
	assert.Equal(t, fakeValueOne, fixture.revealValue("expired/secret"))
}

func TestRekeyKeepsValuesAndRotatesRecipient(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", testSecretName)

	before, _ := fixture.runOK("", "show", testSecretName)

	stdout, _ := fixture.runOK("", "rekey")
	payload := decode(t, stdout)
	assert.InDelta(t, 1, payload["rekeyedVersions"], 0)

	recipient, ok := payload["recipient"].(string)
	require.True(t, ok)
	assert.True(t, strings.HasPrefix(recipient, "age1"))

	// The value still resolves through the new identity, and the old
	// identity survives as a backup.
	assert.Equal(t, fakeValueOne, fixture.revealValue(testSecretName))

	_, err := os.Stat(fixture.identityPath + ".bak")
	require.NoError(t, err, "rekey must keep the old identity as .bak")

	after, _ := fixture.runOK("", "show", testSecretName)
	assert.Equal(t, before, after, "rekey must not change metadata")
}

func TestPasswdRotatesPassphrase(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", testSecretName)

	newPassphraseFile := filepath.Join(t.TempDir(), "new-passphrase")
	require.NoError(t, os.WriteFile(newPassphraseFile, []byte("fake-new-passphrase\n"), 0o600))

	fixture.runOK("", "passwd", "--new-passphrase-file", newPassphraseFile)

	// The old passphrase must stop working.
	_, _, err := fixture.run("", "reveal", testSecretName)
	require.Error(t, err)

	// The new passphrase resolves the same value.
	fixture.passphraseFile = newPassphraseFile
	assert.Equal(t, fakeValueOne, fixture.revealValue(testSecretName))
}

func TestDeletePurgeAndRevive(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", testSecretName)
	fixture.runOK("", "delete", testSecretName)

	// Deleted secrets do not resolve and leave list.
	_, _, err := fixture.run("", "get", testSecretName)
	require.ErrorContains(t, err, "deleted")

	stdout, _ := fixture.runOK("", "list", "--json")
	assert.Equal(t, "[]\n", stdout)

	// show still reports the tombstone.
	stdout, _ = fixture.runOK("", "show", testSecretName)
	assert.NotNil(t, decode(t, stdout)["deletedAt"])

	// purge requires --yes and then destroys envelopes.
	_, _, err = fixture.run("", "purge", testSecretName)
	require.ErrorContains(t, err, "--yes")

	stdout, _ = fixture.runOK("", "purge", testSecretName, "--yes")
	assert.InDelta(t, 1, decode(t, stdout)["destroyedVersions"], 0)

	// A new set revives the name. Version numbers never reset.
	stdout, _ = fixture.runOK(fakeValueTwo+"\n", "set", testSecretName)
	assert.InDelta(t, 2, decode(t, stdout)["version"], 0)
	assert.Equal(t, fakeValueTwo, fixture.revealValue(testSecretName))
}

func TestSetRejectsInvalidName(t *testing.T) {
	fixture := newCLIFixture(t)

	_, _, err := fixture.run(fakeValueOne+"\n", "set", "bad name")
	require.ErrorContains(t, err, "invalid secret name")
}
