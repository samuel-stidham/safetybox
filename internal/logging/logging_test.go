package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/samuel-stidham/safetybox/internal/logging"
	"github.com/samuel-stidham/safetybox/internal/secret"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePlaintext is obviously fake test material, never a real secret.
const fakePlaintext = "fake-log-plaintext-not-real"

// TestSecretValueRedactedThroughHandler logs a real secret.Value
// under a NON-sensitive key, so it exercises the type's own LogValue
// rather than the key denylist. Both handlers must redact.
func TestSecretValueRedactedThroughHandler(t *testing.T) {
	value := secret.New([]byte(fakePlaintext))

	for _, opts := range []logging.Options{{}, {JSON: true}} {
		var buf bytes.Buffer

		logging.New(&buf, opts).Warn("probe", "payload", value)

		assert.Contains(t, buf.String(), "[REDACTED]")
		assert.NotContains(t, buf.String(), fakePlaintext, "LogValue must redact the secret")
	}
}

// TestSensitiveKeyBackstopRedactsRawString covers the ReplaceAttr
// denylist: a raw string logged under a sensitive key is redacted
// even though a plain string has no LogValue of its own.
func TestSensitiveKeyBackstopRedactsRawString(t *testing.T) {
	for _, key := range []string{"passphrase", "value", "plaintext", "identity", "secret", "password", "token"} {
		var buf bytes.Buffer

		logging.New(&buf, logging.Options{}).Warn("probe", key, fakePlaintext)

		assert.Contains(t, buf.String(), "[REDACTED]", "key %q must be redacted", key)
		assert.NotContains(t, buf.String(), fakePlaintext, "raw string under %q must not leak", key)
	}
}

func TestLevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		opts       logging.Options
		logAt      slog.Level
		wantLogged bool
	}{
		{name: "debug suppressed by default", opts: logging.Options{}, logAt: slog.LevelDebug, wantLogged: false},
		{name: "info suppressed by default", opts: logging.Options{}, logAt: slog.LevelInfo, wantLogged: false},
		{name: "warn logged by default", opts: logging.Options{}, logAt: slog.LevelWarn, wantLogged: true},
		{name: "error logged by default", opts: logging.Options{}, logAt: slog.LevelError, wantLogged: true},
		{name: "debug logged when verbose", opts: logging.Options{Verbose: true}, logAt: slog.LevelDebug, wantLogged: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			logger := logging.New(&buf, tt.opts)
			logger.Log(t.Context(), tt.logAt, "probe message")

			if tt.wantLogged {
				assert.Contains(t, buf.String(), "probe message")
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestTextFormatByDefault(t *testing.T) {
	var buf bytes.Buffer

	logging.New(&buf, logging.Options{}).Warn("probe message", "verb", "list")

	assert.Contains(t, buf.String(), "msg=\"probe message\"")
	assert.Contains(t, buf.String(), "verb=list")
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer

	logging.New(&buf, logging.Options{JSON: true}).Warn("probe message", "verb", "list")

	var record map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	assert.Equal(t, "probe message", record["msg"])
	assert.Equal(t, "list", record["verb"])
}

func TestSetupInstallsDefault(t *testing.T) {
	previous := slog.Default()

	t.Cleanup(func() { slog.SetDefault(previous) })

	logger := logging.Setup(logging.Options{})

	assert.Same(t, logger, slog.Default())
}
