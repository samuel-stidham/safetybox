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

func TestExposeReturnsPlaintext(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))

	assert.Equal(t, []byte(fakePlaintext), value.Expose())
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
