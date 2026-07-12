package secret_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/samuel-stidham/safetybox/internal/secret"

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
