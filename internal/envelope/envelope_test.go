package envelope_test

import (
	"bytes"
	"testing"

	"github.com/samuel-stidham/safetybox/v2/internal/envelope"
	"github.com/samuel-stidham/safetybox/v2/internal/secret"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePlaintext is obviously fake test material, never a real secret.
const fakePlaintext = "fake-envelope-payload-not-real"

const testAddress = "api/v1/testing/fake/1"

func newTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()

	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	return identity
}

func TestSealOpenRoundTrip(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), fakePlaintext, "sealed blob must not contain plaintext")

	opened, err := envelope.Open(identity, testAddress, sealed)
	require.NoError(t, err)
	assert.Equal(t, []byte(fakePlaintext), opened.Expose())
}

// TestSealOpenRoundTripLargeValue pins the round trip for payloads past
// the wiping reader's 512-byte growth boundary, so the drain that
// zeroes its outgrown buffers never corrupts a larger plaintext.
func TestSealOpenRoundTripLargeValue(t *testing.T) {
	identity := newTestIdentity(t)
	large := bytes.Repeat([]byte("fake-large-payload-not-real-"), 200)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, secret.New(large))
	require.NoError(t, err)

	opened, err := envelope.Open(identity, testAddress, sealed)
	require.NoError(t, err)
	assert.Equal(t, large, opened.Expose())
}

func TestOpenWrongAddressFails(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)

	tests := []struct {
		name    string
		address string
	}{
		{name: "different secret", address: "api/v1/testing/other/1"},
		{name: "different version", address: "api/v1/testing/fake/2"},
		{name: "empty address", address: ""},
		{name: "prefix of the real address", address: "api/v1/testing/fake"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := envelope.Open(identity, tt.address, sealed)
			require.ErrorIs(t, err, envelope.ErrAddressMismatch)
		})
	}
}

func TestSealRejectsAddressWithSeparator(t *testing.T) {
	identity := newTestIdentity(t)

	_, err := envelope.Seal(identity.Recipient(), "api/v1/bad\naddress/1", secret.New([]byte(fakePlaintext)))
	require.ErrorIs(t, err, envelope.ErrInvalidAddress)
}

func TestOpenWrongIdentityFails(t *testing.T) {
	identity := newTestIdentity(t)
	other := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)

	_, err = envelope.Open(other, testAddress, sealed)
	require.ErrorIs(t, err, envelope.ErrDecryptFailed)
}

func TestOpenCorruptOneByteFails(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)

	for i := range sealed {
		corrupted := make([]byte, len(sealed))
		copy(corrupted, sealed)
		corrupted[i] ^= 0xff

		require.NotPanics(t, func() {
			opened, openErr := envelope.Open(identity, testAddress, corrupted)
			assert.Error(t, openErr, "corrupting byte %d must fail decryption", i)

			if openErr == nil {
				// Belt and braces: a corrupt blob must never
				// yield plaintext silently.
				assert.NotEqual(t, []byte(fakePlaintext), opened.Expose())
			}
		})
	}
}

func TestOpenBlobWithoutEmbeddedAddressFails(t *testing.T) {
	identity := newTestIdentity(t)

	// Encrypt a payload with no address frame at all, bypassing Seal.
	var raw bytes.Buffer

	writer, err := age.Encrypt(&raw, identity.Recipient())
	require.NoError(t, err)

	_, err = writer.Write([]byte("no-separator-in-here"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	_, err = envelope.Open(identity, testAddress, raw.Bytes())
	require.ErrorIs(t, err, envelope.ErrAddressMismatch)
}

func TestOpenTruncatedBlobFails(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)

	tests := []struct {
		name string
		blob []byte
	}{
		{name: "empty", blob: nil},
		{name: "one byte", blob: sealed[:1]},
		{name: "header only", blob: sealed[:min(len(sealed)-1, 100)]},
		{name: "half", blob: sealed[:len(sealed)/2]},
		{name: "one byte short", blob: sealed[:len(sealed)-1]},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := envelope.Open(identity, testAddress, testCase.blob)
			require.ErrorIs(t, err, envelope.ErrDecryptFailed)
		})
	}
}
