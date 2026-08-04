package envelope_test

import (
	"strings"
	"testing"

	"github.com/samuel-stidham/safetybox/v4/internal/envelope"
	"github.com/samuel-stidham/safetybox/v4/internal/secret"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// injectingAddress carries a newline followed by text shaped like one of
// safetybox's own warnings. Printed raw, it becomes its own output line.
const injectingAddress = "api/v1/spoof\nwarning: fake injected line/1"

// TestSealQuotesAnAddressCarryingANewline pins GitHub issue #14. Seal
// refuses a newline in the address, and the refusal used to print the
// address with %s, so the injected text rendered as a separate line of
// stderr. Quoting it keeps the whole message on one line.
func TestSealQuotesAnAddressCarryingANewline(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	value := secret.New([]byte("fake-value-not-real"))
	defer value.Destroy()

	_, err = envelope.Seal(identity.Recipient(), injectingAddress, envelope.Bound{}, value)

	require.Error(t, err)
	require.ErrorIs(t, err, envelope.ErrInvalidFrame)

	assertSingleLine(t, err.Error())
	assert.Contains(t, err.Error(), `\n`, "the newline must appear escaped, not literal")
}

// TestSealQuotesABoundFieldCarryingANewline covers the other framed
// fields, since a vault-write attacker controls the env name and expiry
// columns that migrate and rekey seal from.
func TestSealQuotesABoundFieldCarryingANewline(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	for _, testCase := range []struct {
		name  string
		bound envelope.Bound
	}{
		{name: "env name", bound: envelope.Bound{EnvName: "FAKE\nwarning: injected"}},
		{name: "expiry", bound: envelope.Bound{ExpiresAt: "2099-01-01\nwarning: injected"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value := secret.New([]byte("fake-value-not-real"))
			defer value.Destroy()

			_, err := envelope.Seal(identity.Recipient(), "api/v1/ok/1", testCase.bound, value)

			require.Error(t, err)
			assertSingleLine(t, err.Error())
		})
	}
}

// TestOpenQuotesAnAddressCarryingANewline covers the read side. Every
// "open ..." error interpolates the address, and migrate and rekey build
// addresses from the database name column.
func TestOpenQuotesAnAddressCarryingANewline(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	// Not a valid envelope, which is the point: every refusal path names
	// the address it was asked about.
	_, _, err = envelope.Open(identity, injectingAddress, []byte("not-an-envelope"))

	require.Error(t, err)
	assertSingleLine(t, err.Error())
}

// TestOpenLegacyQuotesAnAddressCarryingANewline covers the v1 path, which
// the original report exercised alongside Seal.
func TestOpenLegacyQuotesAnAddressCarryingANewline(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	_, err = envelope.OpenLegacy(identity, injectingAddress, []byte("not-an-envelope"))

	require.Error(t, err)
	assertSingleLine(t, err.Error())
}

// assertSingleLine fails when an error message spans more than one line,
// which is how the injection showed itself.
func assertSingleLine(t *testing.T, message string) {
	t.Helper()

	assert.NotContains(t, message, "\n",
		"an error message must stay on one line, got %q", message)
	assert.Len(t, strings.Split(message, "\n"), 1,
		"an attacker-controlled newline must not start a new output line")
}
