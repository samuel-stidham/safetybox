package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNonRevealVerbsNeverPrintPlaintext asserts that the fake value
// appears in neither stdout nor stderr of any verb other than reveal,
// including on a wrong-passphrase error path.
func TestNonRevealVerbsNeverPrintPlaintext(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_KEY_ONE")
	fixture.runOK(fakeValueTwo+"\n", "set", "api/two", "--expires", "2020-01-02")

	checks := [][]string{
		{"set", "api/one", "--env-name", "FAKE_KEY_ONE"},
		{"get", "api/one"},
		{"show", "api/one"},
		{"list", "--json"},
		{"stale", "--json"},
		{"rekey"},
	}

	for _, args := range checks {
		stdin := ""
		if args[0] == "set" {
			stdin = fakeValueOne + "\n"
		}

		stdout, stderr, _ := fixture.run(stdin, args...)

		assert.NotContains(t, stdout, fakeValueOne, "%v leaked plaintext on stdout", args)
		assert.NotContains(t, stderr, fakeValueOne, "%v leaked plaintext on stderr", args)
	}

	// Wrong-passphrase error path must not surface plaintext either.
	wrong := filepath.Join(t.TempDir(), "wrong")
	require.NoError(t, os.WriteFile(wrong, []byte("fake-wrong\n"), 0o600))
	fixture.passphraseFile = wrong

	stdout, stderr, err := fixture.run("", "get", "api/one")
	require.Error(t, err)
	assert.NotContains(t, stdout+stderr+err.Error(), fakeValueOne)
}

// TestRevealShellRoundTripsThroughRealShell sources the emitted
// assignments in an actual sh and fish and reads the value back,
// proving the quoting resists a hostile value rather than only
// matching the quoting helper against itself.
func TestRevealShellRoundTripsThroughRealShell(t *testing.T) {
	fixture := newCLIFixture(t)

	hostile := "it's $(echo pwned) `id` \"x\" \\ end"
	fixture.runOK(hostile+"\n", "set", "api/hostile", "--env-name", "FAKE_HOSTILE")

	t.Run("sh", func(t *testing.T) {
		shOut, _ := fixture.runOK("", "reveal", "--env", "--format", "sh")

		out, err := exec.CommandContext(t.Context(), "sh", "-c", shOut+"\nprintf '%s' \"$FAKE_HOSTILE\"").Output()
		require.NoError(t, err)
		assert.Equal(t, hostile, string(out), "sh must read back the literal value")
	})

	t.Run("fish", func(t *testing.T) {
		fishBin, err := exec.LookPath("fish")
		if err != nil {
			t.Skip("fish not installed")
		}

		fishOut, _ := fixture.runOK("", "reveal", "--env", "--format", "fish")

		out, err := exec.CommandContext(t.Context(), fishBin, "-c", fishOut+"\nprintf '%s' \"$FAKE_HOSTILE\"").Output()
		require.NoError(t, err)
		assert.Equal(t, hostile, string(out), "fish must read back the literal value")
	})
}

// TestPassphraseFileRefusesLoosePerms covers M4: a regular passphrase
// file with group/world bits is refused, mirroring the identity check.
func TestPassphraseFileRefusesLoosePerms(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	require.NoError(t, os.Chmod(fixture.passphraseFile, 0o644))

	_, _, err := fixture.run("", "reveal", "api/one")
	require.ErrorContains(t, err, "chmod 600")
}

// TestSetRejectsInvalidEnvName covers L3.
func TestSetRejectsInvalidEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	_, _, err := fixture.run(fakeValueOne+"\n", "set", "api/one", "--env-name", "BAD-DASH")
	require.ErrorContains(t, err, "shell identifier")
}

// TestReadHealsInterruptedRekey covers M5: a crash that left the
// identity at its .new sibling with no identity.age is repaired on the
// next read.
func TestReadHealsInterruptedRekey(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	// Simulate a crash mid-swap: identity.age gone, .new present.
	require.NoError(t, os.Rename(fixture.identityPath, fixture.identityPath+".new"))

	// The next read must self-heal and resolve the secret.
	assert.Equal(t, fakeValueOne, fixture.revealValue("api/one"))

	_, err := os.Stat(fixture.identityPath)
	require.NoError(t, err, "the staged identity must be promoted into place")
}

// TestRekeyRefusesWhenVaultNotOnIdentity simulates the crash window
// where a rekey committed the vault to the staged key but died before
// the identity swap. A re-run must refuse and point at the staged
// key, never delete it.
func TestRekeyRefusesWhenVaultNotOnIdentity(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	// A real rekey moves the old key to .bak and promotes the new one.
	fixture.runOK("", "rekey")

	// Reconstruct the crash state: vault on the new key, identity.age
	// back to the old key, new key stranded at the staged sibling.
	require.NoError(t, os.Rename(fixture.identityPath, fixture.identityPath+".new"))
	require.NoError(t, os.Rename(fixture.identityPath+".bak", fixture.identityPath))

	_, _, err := fixture.run("", "rekey")
	require.ErrorContains(t, err, "not encrypted to the identity")

	_, statErr := os.Stat(fixture.identityPath + ".new")
	require.NoError(t, statErr, "the staged live key must never be deleted")

	// Read verbs in this state must hint at the interrupted rekey.
	_, _, err = fixture.run("", "reveal", "api/one")
	require.ErrorContains(t, err, "interrupted rekey")
}

// TestPasswdHealsInterruptedRekey covers the heal gap: passwd used to
// bypass completeInterruptedRekey and hint at init.
func TestPasswdHealsInterruptedRekey(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	// Simulate a crash mid-swap: identity.age gone, .new present.
	require.NoError(t, os.Rename(fixture.identityPath, fixture.identityPath+".new"))

	newPassphraseFile := filepath.Join(t.TempDir(), "next")
	require.NoError(t, os.WriteFile(newPassphraseFile, []byte("fake-next-passphrase\n"), 0o600))

	fixture.runOK("", "passwd", "--new-passphrase-file", newPassphraseFile)

	_, err := os.Stat(fixture.identityPath)
	require.NoError(t, err, "passwd must promote the staged identity before loading")
}

// TestRevealExplicitNameWithoutEnvNameFailsShellFormat pins the
// fails-loudly contract: an explicitly named secret that cannot
// become an assignment fails the batch instead of emitting nothing
// with exit 0.
func TestRevealExplicitNameWithoutEnvNameFailsShellFormat(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	stdout, _, err := fixture.run("", "reveal", "api/one", "--format", "sh")
	require.ErrorContains(t, err, "has no env name")
	assert.Empty(t, stdout, "nothing may be emitted when an explicit name fails the batch")
}

// TestRevealWarnsOnDuplicateEnvNames pins the collision warning: the
// last assignment wins in the sourcing shell, so the override must be
// called out on stderr.
func TestRevealWarnsOnDuplicateEnvNames(t *testing.T) {
	fixture := newCLIFixture(t)
	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_SHARED")
	fixture.runOK(fakeValueTwo+"\n", "set", "api/two", "--env-name", "FAKE_SHARED")

	stdout, stderr := fixture.runOK("", "reveal", "--env", "--format", "sh")
	assert.Contains(t, stderr, "overrides")
	assert.Contains(t, stdout, fakeValueTwo, "the later assignment still wins")
}

// TestRevealRejectsJSONFlagWithShellFormat pins the flag conflict:
// --json silently did nothing beside --format sh.
func TestRevealRejectsJSONFlagWithShellFormat(t *testing.T) {
	fixture := newCLIFixture(t)

	_, _, err := fixture.run("", "reveal", "--env", "--format", "sh", "--json")
	require.ErrorContains(t, err, "--json applies to json output")
}
