package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuoteSh(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain", value: "fake-value", want: "'fake-value'"},
		{name: "embedded quote", value: "it's", want: `'it'\''s'`},
		{name: "newline survives", value: "a\nb", want: "'a\nb'"},
		{name: "backslash is literal", value: `a\b`, want: `'a\b'`},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, quoteSh(testCase.value))
		})
	}
}

func TestQuoteFish(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "plain", value: "fake-value", want: "'fake-value'"},
		{name: "embedded quote", value: "it's", want: `'it\'s'`},
		{name: "newline survives", value: "a\nb", want: "'a\nb'"},
		{name: "backslash escapes", value: `a\b`, want: `'a\\b'`},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, quoteFish(testCase.value))
		})
	}
}

func TestIsShellIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "upper snake", input: "STRIPE_KEY", want: true},
		{name: "leading underscore", input: "_private2", want: true},
		{name: "leading digit", input: "2LEADING", want: false},
		{name: "dash", input: "BAD-DASH", want: false},
		{name: "space", input: "SPACE D", want: false},
		{name: "equals smuggle", input: "FOO=BAR", want: false},
		{name: "unicode letter", input: "ÜBER", want: false},
		{name: "empty", input: "", want: false},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, isShellIdentifier(testCase.input))
		})
	}
}

func TestRevealMultipleNamesReturnsArray(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one")
	fixture.runOK(fakeValueTwo+"\n", "set", "api/two")

	stdout, _ := fixture.runOK("", "reveal", "api/one", "api/two")

	var outputs []map[string]any

	require.NoError(t, json.Unmarshal([]byte(stdout), &outputs))
	require.Len(t, outputs, 2)
	assert.Equal(t, fakeValueOne, outputs[0]["value"])
	assert.Equal(t, fakeValueTwo, outputs[1]["value"])
}

func TestRevealMissingNameFailsWholeBatch(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	_, _, err := fixture.run("", "reveal", "api/one", "api/missing")
	require.ErrorContains(t, err, "not found")
}

func TestRevealEnvFilterEmitsShellAssignments(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_KEY_ONE")
	fixture.runOK(fakeValueTwo+"\n", "set", "api/two", "--env-name", "FAKE_KEY_TWO")
	fixture.runOK(fakeValueThree+"\n", "set", "no/env/name")

	stdout, _ := fixture.runOK("", "reveal", "--env", "--format", "sh")
	assert.Equal(t,
		"export FAKE_KEY_ONE='"+fakeValueOne+"'\n"+
			"export FAKE_KEY_TWO='"+fakeValueTwo+"'\n",
		stdout)
	assert.NotContains(t, stdout, fakeValueThree, "--env must not select unnamed secrets")

	stdout, _ = fixture.runOK("", "reveal", "--env", "--format", "fish")
	assert.Equal(t,
		"set -gx FAKE_KEY_ONE '"+fakeValueOne+"'\n"+
			"set -gx FAKE_KEY_TWO '"+fakeValueTwo+"'\n",
		stdout)
}

func TestRevealPrefixFilterScopesTheBatch(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "projects/app/token", "--env-name", "FAKE_APP_TOKEN")
	fixture.runOK(fakeValueTwo+"\n", "set", "global/other", "--env-name", "FAKE_OTHER")

	stdout, _ := fixture.runOK("", "reveal", "--prefix", "projects/app", "--format", "sh")
	assert.Equal(t, "export FAKE_APP_TOKEN='"+fakeValueOne+"'\n", stdout)

	// Without an env name the secret is skipped with a warning, never
	// silently dropped.
	fixture.runOK(fakeValueThree+"\n", "set", "projects/app/unnamed")

	stdout, stderr := fixture.runOK("", "reveal", "--prefix", "projects/app", "--format", "sh")
	assert.NotContains(t, stdout, fakeValueThree)
	assert.Contains(t, stderr, "projects/app/unnamed")
	assert.Contains(t, stderr, "no env name")
}

func TestRevealShellFormatQuotesHostileValues(t *testing.T) {
	fixture := newCLIFixture(t)

	hostile := "it's $(uname) `id` \\n"

	fixture.runOK(hostile+"\n", "set", "api/hostile", "--env-name", "FAKE_HOSTILE")

	stdout, _ := fixture.runOK("", "reveal", "--env", "--format", "sh")
	assert.Equal(t, "export FAKE_HOSTILE="+quoteSh(hostile)+"\n", stdout)

	stdout, _ = fixture.runOK("", "reveal", "--env", "--format", "fish")
	assert.Equal(t, "set -gx FAKE_HOSTILE "+quoteFish(hostile)+"\n", stdout)
}

func TestRevealBatchJSONIncludesEnvName(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one", "--env-name", "FAKE_KEY_ONE")

	stdout, _ := fixture.runOK("", "reveal", "--env")

	var outputs []map[string]any

	require.NoError(t, json.Unmarshal([]byte(stdout), &outputs))
	require.Len(t, outputs, 1)
	assert.Equal(t, "FAKE_KEY_ONE", outputs[0]["envName"])
	assert.Equal(t, fakeValueOne, outputs[0]["value"])
}

func TestRevealEmptyFilterMatchIsEmptyArray(t *testing.T) {
	fixture := newCLIFixture(t)

	stdout, _ := fixture.runOK("", "reveal", "--prefix", "nothing/here")
	assert.Equal(t, "[]", strings.TrimSpace(stdout))
}

func TestRevealEmptyMatchNeverUnlocksIdentity(t *testing.T) {
	fixture := newCLIFixture(t)

	// A wrong passphrase fails any identity unlock, so success here
	// proves an empty match never touches the identity at all.
	wrongPassphraseFile := filepath.Join(t.TempDir(), "wrong")
	require.NoError(t, os.WriteFile(wrongPassphraseFile, []byte("fake-wrong-passphrase\n"), 0o600))
	fixture.passphraseFile = wrongPassphraseFile

	stdout, _ := fixture.runOK("", "reveal", "--prefix", "nothing/here")
	assert.Equal(t, "[]", strings.TrimSpace(stdout))
}

func TestRevealSingleNameKeepsObjectShape(t *testing.T) {
	fixture := newCLIFixture(t)

	fixture.runOK(fakeValueOne+"\n", "set", "api/one")

	stdout, _ := fixture.runOK("", "reveal", "api/one")
	assert.Equal(t, fakeValueOne, decode(t, stdout)["value"], "single-name reveal must stay one JSON object")
}

func TestRevealRejectsContradictorySelections(t *testing.T) {
	fixture := newCLIFixture(t)

	_, _, err := fixture.run("", "reveal", "api/one", "--env")
	require.ErrorContains(t, err, "not both")

	_, _, err = fixture.run("", "reveal")
	require.ErrorContains(t, err, "at least one name")

	_, _, err = fixture.run("", "reveal", "--env", "--format", "csv")
	require.ErrorContains(t, err, "not json, sh, or fish")
}
