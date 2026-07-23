package secret_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"testing/iotest"

	"github.com/samuel-stidham/safetybox/v3/internal/secret"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePlaintext is obviously fake test material, never a real secret.
const fakePlaintext = "fake-test-secret-value-not-real"

const redacted = "[REDACTED]"

type leakRendering struct {
	name   string
	render func(t *testing.T, value secret.Value) string
}

func fmtRenderings() []leakRendering {
	return []leakRendering{
		{name: "fmt %v", render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%v", value) }},
		{name: "fmt %+v", render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%+v", value) }},
		{name: "fmt %#v", render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%#v", value) }},
		{name: "fmt %s", render: func(_ *testing.T, value secret.Value) string { return value.String() }},
		{
			name: "fmt %v on struct field",
			render: func(_ *testing.T, value secret.Value) string {
				return fmt.Sprintf("%v", struct{ Value secret.Value }{Value: value})
			},
		},
		{
			name:   "fmt %d numeric verb",
			render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%d", value) },
		},
		{
			name:   "fmt %c numeric verb",
			render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%c", value) },
		},
		{
			name:   "fmt %x hex verb",
			render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%x", value) },
		},
		{
			name:   "fmt %d on pointer",
			render: func(_ *testing.T, value secret.Value) string { return fmt.Sprintf("%d", &value) },
		},
	}
}

// unexportedFieldRenderings cover the path fmt reflection takes when a
// Value sits in another struct's unexported field, where fmt cannot
// dispatch Format. These must not leak plaintext, though they render
// the pointer rather than the redaction marker, so they are asserted
// separately from the marker-bearing renderings.
func unexportedFieldRenderings() []leakRendering {
	type holder struct{ value secret.Value }

	return []leakRendering{
		{
			name: "fmt %v on unexported field",
			render: func(_ *testing.T, value secret.Value) string {
				return fmt.Sprintf("%v", holder{value: value})
			},
		},
		{
			name: "fmt %+v on unexported field",
			render: func(_ *testing.T, value secret.Value) string {
				return fmt.Sprintf("%+v", holder{value: value})
			},
		},
		{
			name: "fmt %#v on unexported field",
			render: func(_ *testing.T, value secret.Value) string {
				return fmt.Sprintf("%#v", holder{value: value})
			},
		},
		{
			name: "fmt %d on unexported field",
			render: func(_ *testing.T, value secret.Value) string {
				return fmt.Sprintf("%d", holder{value: value})
			},
		},
		{
			name: "slog with unexported field struct",
			render: func(_ *testing.T, value secret.Value) string {
				var buf bytes.Buffer

				slog.New(slog.NewTextHandler(&buf, nil)).Warn("cfg", "cfg", holder{value: value})

				return buf.String()
			},
		},
	}
}

func encodeRenderings() []leakRendering {
	return []leakRendering{
		{
			name: "json.Marshal",
			render: func(t *testing.T, value secret.Value) string {
				t.Helper()

				out, err := json.Marshal(value)
				require.NoError(t, err)

				return string(out)
			},
		},
		{
			name: "json.Marshal on struct field",
			render: func(t *testing.T, value secret.Value) string {
				t.Helper()

				wrapper := struct {
					Value secret.Value `json:"value"`
				}{Value: value}

				out, err := json.Marshal(wrapper)
				require.NoError(t, err)

				return string(out)
			},
		},
		{
			name: "slog text handler",
			render: func(_ *testing.T, value secret.Value) string {
				var buf bytes.Buffer

				slog.New(slog.NewTextHandler(&buf, nil)).Warn("storing secret", "value", value)

				return buf.String()
			},
		},
		{
			name: "slog json handler",
			render: func(_ *testing.T, value secret.Value) string {
				var buf bytes.Buffer

				slog.New(slog.NewJSONHandler(&buf, nil)).Warn("storing secret", "value", value)

				return buf.String()
			},
		},
	}
}

func TestSecretValueNeverLeaks(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))

	renderings := append(fmtRenderings(), encodeRenderings()...)

	for _, tt := range renderings {
		t.Run(tt.name, func(t *testing.T) {
			out := tt.render(t, value)

			assert.NotContains(t, out, fakePlaintext, "plaintext leaked through %s", tt.name)
			assert.Contains(t, out, redacted, "redaction marker missing from %s", tt.name)
		})
	}
}

// TestSecretValueUnexportedFieldNeverLeaks covers the fmt-reflection
// path that method dispatch cannot reach. Plaintext must be absent.
// The redaction marker is not required because the pointer renders as
// an address.
func TestSecretValueUnexportedFieldNeverLeaks(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))

	for _, tt := range unexportedFieldRenderings() {
		t.Run(tt.name, func(t *testing.T) {
			out := tt.render(t, value)

			assert.NotContains(t, out, fakePlaintext, "plaintext leaked through %s", tt.name)
			// The decimal byte rendering is the other shape a leak
			// takes, so guard against it explicitly.
			assert.NotContains(t, out, "102 97 107", "decimal byte leak through %s", tt.name)
		})
	}
}

func TestExposeReturnsPlaintext(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))

	assert.Equal(t, []byte(fakePlaintext), value.Expose())
}

// TestExposeAliasesInternalStorage pins the documented contract: the
// returned slice aliases the Value's storage and copies share it.
func TestExposeAliasesInternalStorage(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))
	copyOfValue := value

	value.Expose()[0] = 'X'

	assert.Equal(t, byte('X'), copyOfValue.Expose()[0], "copies of a Value share one backing array")
}

func TestMarshalJSONExactOutput(t *testing.T) {
	out, err := json.Marshal(secret.New([]byte(fakePlaintext)))

	require.NoError(t, err)
	assert.Equal(t, `"[REDACTED]"`, string(out))
}

func TestEmptyValue(t *testing.T) {
	value := secret.New(nil)

	assert.Empty(t, value.Expose())
	assert.Equal(t, redacted, value.String())
}

func TestNewCopiesInput(t *testing.T) {
	input := []byte(fakePlaintext)
	value := secret.New(input)

	// Mutating the caller's slice must not change the held value.
	for i := range input {
		input[i] = 'x'
	}

	assert.Equal(t, []byte(fakePlaintext), value.Expose())
}

// TestDestroyZeroesPlaintext pins that Destroy wipes the backing array
// and drops the reference, so Expose returns nil afterward.
func TestDestroyZeroesPlaintext(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))
	exposed := value.Expose()

	value.Destroy()

	assert.Nil(t, value.Expose(), "Destroy must drop the reference")

	for i, b := range exposed {
		assert.Equal(t, byte(0), b, "byte %d must be zeroed", i)
	}
}

// TestDestroyWipesCopies pins that copies share one backing array, so a
// single Destroy wipes every copy of the Value.
func TestDestroyWipesCopies(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))
	copyOfValue := value

	value.Destroy()

	assert.Nil(t, copyOfValue.Expose(), "Destroy on one copy must wipe them all")
}

// TestDestroyIsIdempotent pins that a second Destroy is safe.
func TestDestroyIsIdempotent(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))

	value.Destroy()

	assert.NotPanics(t, func() { value.Destroy() })
}

// TestReadAllWiping pins that the wiping reader returns the exact input
// across sizes that span its 512-byte growth boundary, so the wiping of
// intermediate buffers never corrupts the content.
func TestReadAllWiping(t *testing.T) {
	for _, size := range []int{0, 1, 511, 512, 513, 1536, 5000} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			want := bytes.Repeat([]byte("x"), size)

			got, err := secret.ReadAllWiping(bytes.NewReader(want))
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

// TestReadAllWipingSurfacesReadError pins that a read failure is wrapped
// and returned rather than swallowed.
func TestReadAllWipingSurfacesReadError(t *testing.T) {
	_, err := secret.ReadAllWiping(iotest.ErrReader(errors.New("boom")))

	require.Error(t, err)
	assert.ErrorContains(t, err, "boom")
}

// TestReadAllWipingReturnsNothingOnError pins that a read failure hands
// back no partial content. The bytes read before the failure would
// otherwise sit unzeroed on the heap in a slice every caller discards.
func TestReadAllWipingReturnsNothingOnError(t *testing.T) {
	partial := io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte("x"), 700)),
		iotest.ErrReader(errors.New("boom")),
	)

	got, err := secret.ReadAllWiping(partial)

	require.Error(t, err)
	assert.Nil(t, got, "a failed read must not return partial content")
}

// TestReadAllWipingHandlesDataWithEOF pins the io.Reader contract shape
// where the final data arrives together with io.EOF in one call.
func TestReadAllWipingHandlesDataWithEOF(t *testing.T) {
	want := bytes.Repeat([]byte("x"), 600)

	got, err := secret.ReadAllWiping(iotest.DataErrReader(bytes.NewReader(want)))

	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// TestReadAllWipingTreatsWrappedEOFAsFailure pins io.ReadAll's exact
// end-of-input contract: only a bare io.EOF is success. An error that
// wraps io.EOF is a genuine failure, and reading it as a clean end
// would silently return truncated secret data.
func TestReadAllWipingTreatsWrappedEOFAsFailure(t *testing.T) {
	torn := io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte("x"), 100)),
		iotest.ErrReader(fmt.Errorf("stream torn down: %w", io.EOF)),
	)

	got, err := secret.ReadAllWiping(torn)

	require.Error(t, err)
	require.ErrorIs(t, err, io.EOF, "the wrapped cause must stay inspectable")
	assert.Nil(t, got, "a wrapped EOF must not return truncated content as success")
}

// windowCapturingReader keeps the first buffer window it is handed, so
// a test can inspect the outgrown backing array after the read ends.
type windowCapturingReader struct {
	src      io.Reader
	captured []byte
}

func (r *windowCapturingReader) Read(p []byte) (int, error) {
	if r.captured == nil {
		r.captured = p
	}

	return r.src.Read(p)
}

// TestReadAllWipingZeroesOutgrownBuffer pins the feature itself: after
// the reader outgrows its first buffer, that buffer's bytes are zeroed
// rather than left holding a secret prefix for the garbage collector.
func TestReadAllWipingZeroesOutgrownBuffer(t *testing.T) {
	input := bytes.Repeat([]byte("x"), 700)
	reader := &windowCapturingReader{src: bytes.NewReader(input)}

	got, err := secret.ReadAllWiping(reader)
	require.NoError(t, err)
	require.Equal(t, input, got, "content must survive the growth")

	require.NotNil(t, reader.captured)

	for i, b := range reader.captured {
		require.Equal(t, byte(0), b, "outgrown buffer byte %d must be zeroed", i)
	}
}
