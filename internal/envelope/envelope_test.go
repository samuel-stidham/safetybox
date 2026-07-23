package envelope_test

import (
	"bytes"
	"testing"

	"github.com/samuel-stidham/safetybox/v3/internal/envelope"
	"github.com/samuel-stidham/safetybox/v3/internal/secret"

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

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, envelope.Bound{}, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), fakePlaintext, "sealed blob must not contain plaintext")

	opened, bound, err := envelope.Open(identity, testAddress, sealed)
	require.NoError(t, err)
	assert.Equal(t, []byte(fakePlaintext), opened.Expose())
	assert.Equal(t, envelope.Bound{}, bound, "an empty bound must round-trip empty")
}

// TestSealOpenBindsMetadata pins that the env name and expiry seal into
// the envelope and come back on open, so a read can compare them to the
// plaintext columns.
func TestSealOpenBindsMetadata(t *testing.T) {
	identity := newTestIdentity(t)
	want := envelope.Bound{EnvName: "FAKE_KEY", ExpiresAt: "2030-01-02T03:04:05Z"}

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, want, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), "FAKE_KEY", "the env name must be inside the ciphertext")

	opened, bound, err := envelope.Open(identity, testAddress, sealed)
	require.NoError(t, err)
	assert.Equal(t, []byte(fakePlaintext), opened.Expose())
	assert.Equal(t, want, bound, "the bound metadata must round-trip")
}

// TestSealRejectsNewlineInBound pins that a newline in a bound field is
// refused, since it would corrupt the header framing.
func TestSealRejectsNewlineInBound(t *testing.T) {
	identity := newTestIdentity(t)

	_, err := envelope.Seal(identity.Recipient(), testAddress,
		envelope.Bound{EnvName: "FAKE\nKEY"}, secret.New([]byte(fakePlaintext)))
	require.ErrorIs(t, err, envelope.ErrInvalidFrame)
}

// TestSealOpenRoundTripLargeValue pins the round trip for payloads past
// the wiping reader's 512-byte growth boundary.
func TestSealOpenRoundTripLargeValue(t *testing.T) {
	identity := newTestIdentity(t)
	large := bytes.Repeat([]byte("fake-large-payload-not-real-"), 200)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, envelope.Bound{}, secret.New(large))
	require.NoError(t, err)

	opened, _, err := envelope.Open(identity, testAddress, sealed)
	require.NoError(t, err)
	assert.Equal(t, large, opened.Expose())
}

func TestOpenWrongAddressFails(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, envelope.Bound{}, secret.New([]byte(fakePlaintext)))
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
			_, _, err := envelope.Open(identity, tt.address, sealed)
			require.ErrorIs(t, err, envelope.ErrAddressMismatch)
		})
	}
}

func TestSealRejectsAddressWithSeparator(t *testing.T) {
	identity := newTestIdentity(t)

	_, err := envelope.Seal(identity.Recipient(), "api/v1/bad\naddress/1",
		envelope.Bound{}, secret.New([]byte(fakePlaintext)))
	require.ErrorIs(t, err, envelope.ErrInvalidFrame)
}

func TestOpenWrongIdentityFails(t *testing.T) {
	identity := newTestIdentity(t)
	other := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, envelope.Bound{}, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)

	_, _, err = envelope.Open(other, testAddress, sealed)
	require.ErrorIs(t, err, envelope.ErrDecryptFailed)
}

func TestOpenCorruptOneByteFails(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, envelope.Bound{}, secret.New([]byte(fakePlaintext)))
	require.NoError(t, err)

	for i := range sealed {
		corrupted := make([]byte, len(sealed))
		copy(corrupted, sealed)
		corrupted[i] ^= 0xff

		require.NotPanics(t, func() {
			opened, _, openErr := envelope.Open(identity, testAddress, corrupted)
			assert.Error(t, openErr, "corrupting byte %d must fail decryption", i)

			if openErr == nil {
				// Belt and braces: a corrupt blob must never yield
				// plaintext silently.
				assert.NotEqual(t, []byte(fakePlaintext), opened.Expose())
			}
		})
	}
}

// TestOpenLegacyFrameFails pins that an envelope without the v2 version
// tag is refused, which blocks a downgrade to the older unbound frame.
func TestOpenLegacyFrameFails(t *testing.T) {
	identity := newTestIdentity(t)

	// A v1-style frame: the address then a newline then the value, with
	// no version tag and no bound header.
	var raw bytes.Buffer

	writer, err := age.Encrypt(&raw, identity.Recipient())
	require.NoError(t, err)

	_, err = writer.Write([]byte(testAddress + "\n" + fakePlaintext))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	_, _, err = envelope.Open(identity, testAddress, raw.Bytes())
	require.ErrorIs(t, err, envelope.ErrAddressMismatch)
}

// sealLegacyFrame builds a version 1 envelope by hand: the address, a
// newline, and the value, with no version tag.
func sealLegacyFrame(t *testing.T, recipient age.Recipient, address, value string) []byte {
	t.Helper()

	var raw bytes.Buffer

	writer, err := age.Encrypt(&raw, recipient)
	require.NoError(t, err)

	_, err = writer.Write([]byte(address + "\n" + value))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	return raw.Bytes()
}

// TestOpenLegacyRoundTrip pins that the legacy reader recovers a value
// from a version 1 frame, which the migration relies on.
func TestOpenLegacyRoundTrip(t *testing.T) {
	identity := newTestIdentity(t)
	blob := sealLegacyFrame(t, identity.Recipient(), testAddress, fakePlaintext)

	value, err := envelope.OpenLegacy(identity, testAddress, blob)
	require.NoError(t, err)
	assert.Equal(t, []byte(fakePlaintext), value.Expose())
}

// TestOpenLegacyWrongAddressFails pins that the legacy reader still
// checks the embedded address.
func TestOpenLegacyWrongAddressFails(t *testing.T) {
	identity := newTestIdentity(t)
	blob := sealLegacyFrame(t, identity.Recipient(), testAddress, fakePlaintext)

	_, err := envelope.OpenLegacy(identity, "api/v1/testing/other/1", blob)
	require.ErrorIs(t, err, envelope.ErrAddressMismatch)
}

func TestOpenBlobWithoutHeaderFails(t *testing.T) {
	identity := newTestIdentity(t)

	// Encrypt a payload with no header frame at all, bypassing Seal.
	var raw bytes.Buffer

	writer, err := age.Encrypt(&raw, identity.Recipient())
	require.NoError(t, err)

	_, err = writer.Write([]byte("no-terminator-in-here"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	_, _, err = envelope.Open(identity, testAddress, raw.Bytes())
	require.ErrorIs(t, err, envelope.ErrAddressMismatch)
}

func TestOpenTruncatedBlobFails(t *testing.T) {
	identity := newTestIdentity(t)

	sealed, err := envelope.Seal(identity.Recipient(), testAddress, envelope.Bound{}, secret.New([]byte(fakePlaintext)))
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
			_, _, err := envelope.Open(identity, testAddress, testCase.blob)
			require.ErrorIs(t, err, envelope.ErrDecryptFailed)
		})
	}
}
