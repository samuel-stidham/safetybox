// Package logging configures the process-wide structured logger.
//
// The text path renders through charmbracelet/log for styled,
// leveled records. The JSON path stays on the stdlib handler so the
// machine format never shifts under log shippers. Both paths redact
// any leaf attribute whose key names secret-bearing content,
// matched as a standalone suffix of the key.
//
// Log operations, never operand values. Secret plaintext must never
// reach a log record. secret.Value enforces this via LogValue,
// but call sites still must not pass raw byte slices.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/charmbracelet/log"
)

// redactSensitiveKeys replaces the value of any attribute whose key
// names secret-bearing content, regardless of the value's type.
// secret.Value already redacts itself. This is a defense-in-depth
// backstop for a raw string or []byte logged under one of these keys
// by mistake. Group keys are left alone so only leaf attributes are
// affected.
func redactSensitiveKeys(_ []string, attr slog.Attr) slog.Attr {
	if isSensitiveKey(attr.Key) {
		attr.Value = slog.StringValue("[REDACTED]")
	}

	return attr
}

// isSensitiveKey reports whether key names secret-bearing content.
// A key matches when a denylist word is its ASCII-case-insensitive
// suffix and the word stands alone: as the whole key, as a segment
// after '_', '-', or '.', or as a camelCase hump such as ApiToken.
// The hump rule also fires on an all-caps key such as APIKEY, which
// over-redacts by design so the backstop fails closed. EqualFold
// folds Unicode, but the suffix anchor is byte-length and every
// denylist word is pure ASCII, so a multi-byte rune can never
// align. The match is ASCII in effect. Substring matching is
// deliberately absent so operational keys such as identity_path
// and vault_path keep rendering. Lowercase concatenations such as
// apikey have no separator or hump, so the common ones appear as
// denylist words in their own right.
func isSensitiveKey(key string) bool {
	for _, word := range [...]string{
		"passphrase", "value", "plaintext", "identity",
		"secret", "password", "token", "key",
		"passwd", "credential", "credentials", "creds",
		"apikey", "authtoken", "secretkey", "privatekey",
		"privkey", "sshkey",
	} {
		start := len(key) - len(word)
		if start < 0 || !strings.EqualFold(key[start:], word) {
			continue
		}

		if start == 0 {
			return true
		}

		if prev := key[start-1]; prev == '_' || prev == '-' || prev == '.' {
			return true
		}

		if key[start] >= 'A' && key[start] <= 'Z' {
			return true
		}
	}

	return false
}

// redactingHandler resolves LogValuers and applies the sensitive-key
// backstop before a record reaches the wrapped charm handler, which
// has no ReplaceAttr hook. Resolution must happen here: charm formats
// unresolved values with fmt, which would bypass LogValue on types
// whose fmt output differs from their log value.
type redactingHandler struct {
	next slog.Handler
}

// Enabled defers to the wrapped handler, which owns the level.
func (h redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle rebuilds the record with redacted attributes. The incoming
// record may be shared with other handlers, so it is never mutated.
func (h redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)

	record.Attrs(func(attr slog.Attr) bool {
		clean.AddAttrs(redactAttrs(attr)...)

		return true
	})

	if err := h.next.Handle(ctx, clean); err != nil {
		return fmt.Errorf("write log record: %w", err)
	}

	return nil
}

// WithAttrs redacts logger-scoped attributes at attachment time. The
// wrapped handler renders them later without another pass through
// Handle.
func (h redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		clean = append(clean, redactAttrs(attr)...)
	}

	return redactingHandler{next: h.next.WithAttrs(clean)}
}

// WithGroup keeps the wrapper around the grouped handler so later
// attributes still pass through redaction. Group names never carry
// secrets, only leaf attributes do.
func (h redactingHandler) WithGroup(name string) slog.Handler {
	return redactingHandler{next: h.next.WithGroup(name)}
}

// redactAttrs resolves a LogValuer chain, recurses into groups, and
// applies the sensitive-key backstop to leaf attributes. It returns a
// slice because a group with an empty key contributes its members
// directly, mirroring the stdlib handlers. Charm drops any attribute
// whose key is empty, so re-wrapping such a group would silently
// discard its members.
func redactAttrs(attr slog.Attr) []slog.Attr {
	attr.Value = attr.Value.Resolve()

	if attr.Value.Kind() != slog.KindGroup {
		return []slog.Attr{redactSensitiveKeys(nil, attr)}
	}

	members := attr.Value.Group()
	clean := make([]slog.Attr, 0, len(members))

	for _, member := range members {
		clean = append(clean, redactAttrs(member)...)
	}

	if attr.Key == "" {
		return clean
	}

	attr.Value = slog.GroupValue(clean...)

	return []slog.Attr{attr}
}

// Options control how the logger is built.
type Options struct {
	// Verbose lowers the level from Info to Debug.
	Verbose bool
	// JSON switches the handler from text to JSON.
	JSON bool
}

// New builds a logger writing to w. The text path renders through
// charm for human-readable output. The JSON path stays on the stdlib
// handler so the machine format never shifts under log shippers.
func New(w io.Writer, opts Options) *slog.Logger {
	level := slog.LevelInfo
	if opts.Verbose {
		level = slog.LevelDebug
	}

	if opts.JSON {
		handlerOpts := &slog.HandlerOptions{Level: level, ReplaceAttr: redactSensitiveKeys}

		return slog.New(slog.NewJSONHandler(w, handlerOpts))
	}

	charm := log.NewWithOptions(w, log.Options{Level: log.Level(level)})

	return slog.New(redactingHandler{next: charm})
}

// Setup builds a logger on w and installs it as the slog default.
func Setup(w io.Writer, opts Options) *slog.Logger {
	logger := New(w, opts)
	slog.SetDefault(logger)

	return logger
}
