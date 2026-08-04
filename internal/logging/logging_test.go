package logging_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/samuel-stidham/safetybox/v4/internal/logging"
	"github.com/samuel-stidham/safetybox/v4/internal/secret"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePlaintext is obviously fake test material, never a real secret.
const fakePlaintext = "fake-log-plaintext-not-real"

// fmtLeaker redacts through LogValue and leaks through String. It
// exists so a test can tell the two rendering paths apart: charm
// formats attribute values with fmt, so any unresolved value of this
// type prints its plaintext.
type fmtLeaker struct{}

// LogValue is the redacting path, used only after slog resolution.
func (fmtLeaker) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// String is the leaking path, reached by fmt when nothing resolved
// the value first.
func (fmtLeaker) String() string { return fakePlaintext }

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

// TestSensitiveKeyBackstopRedactsRawString covers the sensitive-key
// denylist: a raw string logged under a sensitive key is redacted
// even though a plain string has no LogValue of its own. Case
// variants and compound keys pin the suffix-segment matcher.
func TestSensitiveKeyBackstopRedactsRawString(t *testing.T) {
	keys := []string{
		"passphrase", "value", "plaintext", "identity", "secret",
		"password", "token", "key",
		"Password", "PASSWORD", "Token", "TOKEN",
		"api_token", "API_TOKEN", "API-Token", "ApiToken",
		"client_secret", "DB-Password", "db.password", "api_key",
		"passwd", "Passwd", "PASSWD", "db_passwd", "DbPasswd",
		"apikey", "Apikey", "x-apikey", "authtoken", "secretkey",
		"privatekey", "privkey", "sshkey",
		"credential", "credentials", "creds",
		"aws_credentials", "AwsCreds",
	}
	for _, key := range keys {
		for _, opts := range []logging.Options{{}, {JSON: true}} {
			var buf bytes.Buffer

			logging.New(&buf, opts).Warn("probe", key, fakePlaintext)

			assert.Contains(t, buf.String(), "[REDACTED]", "key %q must be redacted", key)
			assert.NotContains(t, buf.String(), fakePlaintext, "raw string under %q must not leak", key)
		}
	}
}

// TestSensitiveKeyBackstopLeavesOperationalKeys pins every attribute
// key the codebase logs today. None may redact: the matcher compares
// whole trailing segments, never substrings, so identity_path and
// vault_path keep rendering. monkey and sacred pin the boundary rules
// against careless denylist growth.
func TestSensitiveKeyBackstopLeavesOperationalKeys(t *testing.T) {
	keys := []string{
		"identity_path", "vault_path", "lock_path", "name", "env_name",
		"recipient", "expires_at", "stored_as", "count", "reason",
		"previous", "mode", "chmod", "label", "loose_path", "error",
		"version", "entries", "skipped", "injected", "not_injected",
		"monkey", "sacred",
	}
	for _, key := range keys {
		for _, opts := range []logging.Options{{}, {JSON: true}} {
			var buf bytes.Buffer

			logging.New(&buf, opts).Warn("probe", key, "operational-detail")

			assert.Contains(t, buf.String(), "operational-detail", "key %q must keep rendering", key)
			assert.NotContains(t, buf.String(), "[REDACTED]", "key %q must not be redacted", key)
		}
	}
}

// TestRedactsLoggerScopedAttrs covers With-scoped attributes on both
// handlers. Attributes attached via With bypass the charm wrapper's
// per-record Handle pass, so redaction must also run at attachment
// time. The JSON path pins the stdlib handler applying ReplaceAttr to
// preformatted WithAttrs attributes.
func TestRedactsLoggerScopedAttrs(t *testing.T) {
	for _, opts := range []logging.Options{{}, {JSON: true}} {
		var buf bytes.Buffer

		logging.New(&buf, opts).With("password", fakePlaintext).Warn("probe")

		assert.Contains(t, buf.String(), "[REDACTED]")
		assert.NotContains(t, buf.String(), fakePlaintext)
	}
}

// TestRedactsGroupedAttrs covers group recursion on both handlers: a
// sensitive leaf inside an inline group must still be redacted. The
// JSON path pins ReplaceAttr visiting group-nested leaves.
func TestRedactsGroupedAttrs(t *testing.T) {
	for _, opts := range []logging.Options{{}, {JSON: true}} {
		var buf bytes.Buffer

		logging.New(&buf, opts).Warn("probe", slog.Group("conn", slog.String("token", fakePlaintext)))

		assert.Contains(t, buf.String(), "[REDACTED]")
		assert.NotContains(t, buf.String(), fakePlaintext)
	}
}

// TestRedactsAfterWithGroup keeps redaction alive across WithGroup on
// both handlers. The charm wrapper must stay wrapped around the
// grouped handler, and the stdlib JSON handler must keep applying
// ReplaceAttr to attributes logged under an open group.
func TestRedactsAfterWithGroup(t *testing.T) {
	for _, opts := range []logging.Options{{}, {JSON: true}} {
		var buf bytes.Buffer

		logging.New(&buf, opts).WithGroup("conn").Warn("probe", "password", fakePlaintext)

		assert.Contains(t, buf.String(), "[REDACTED]")
		assert.NotContains(t, buf.String(), fakePlaintext)
	}
}

// TestCharmPathResolvesLogValuer pins the middleware's Resolve call.
// The secret.Value tests cannot pin it, since that type also redacts
// through its fmt methods, so the text path would still look clean
// with Resolve deleted. fmtLeaker redacts only through LogValue, so
// charm's fmt-based rendering prints the plaintext unless the record
// was resolved before it arrived. The key is non-sensitive, which
// keeps the denylist backstop out of the result.
func TestCharmPathResolvesLogValuer(t *testing.T) {
	var buf bytes.Buffer

	logging.New(&buf, logging.Options{}).Warn("probe", "payload", fmtLeaker{})

	assert.Contains(t, buf.String(), "[REDACTED]")
	assert.NotContains(t, buf.String(), fakePlaintext)
}

// TestCharmPathInlinesEmptyKeyGroup mirrors stdlib handler semantics:
// a group with an empty key contributes its members directly. Charm
// drops any attribute whose key is empty, so a re-wrapped group would
// take its members down with it and the record would lose the field
// entirely rather than redact it.
func TestCharmPathInlinesEmptyKeyGroup(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "0")

	var buf bytes.Buffer

	logging.New(&buf, logging.Options{}).Warn("probe", slog.Group("", slog.String("token", fakePlaintext)))

	assert.Contains(t, buf.String(), "token=[REDACTED]")
	assert.NotContains(t, buf.String(), fakePlaintext)
}

func TestLevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		opts       logging.Options
		logAt      slog.Level
		wantLogged bool
	}{
		{name: "debug suppressed by default", opts: logging.Options{}, logAt: slog.LevelDebug, wantLogged: false},
		{name: "info logged by default", opts: logging.Options{}, logAt: slog.LevelInfo, wantLogged: true},
		{name: "warn logged by default", opts: logging.Options{}, logAt: slog.LevelWarn, wantLogged: true},
		{name: "error logged by default", opts: logging.Options{}, logAt: slog.LevelError, wantLogged: true},
		{name: "debug logged when verbose", opts: logging.Options{Verbose: true}, logAt: slog.LevelDebug, wantLogged: true},
		{
			name: "debug suppressed by default json", opts: logging.Options{JSON: true},
			logAt: slog.LevelDebug, wantLogged: false,
		},
		{name: "info logged by default json", opts: logging.Options{JSON: true}, logAt: slog.LevelInfo, wantLogged: true},
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

// TestTextFormatByDefault pins the charm text shape: level tag first,
// no timestamp, logfmt-style attributes. CLICOLOR_FORCE is pinned off
// because termenv honors it even on a non-TTY writer, which would
// wrap the assertion targets in escape codes.
func TestTextFormatByDefault(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "0")

	var buf bytes.Buffer

	logging.New(&buf, logging.Options{}).Warn("probe message", "verb", "list")

	assert.Equal(t, "WARN probe message verb=list\n", buf.String())
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

	logger := logging.Setup(io.Discard, logging.Options{})

	assert.Same(t, logger, slog.Default())
}
