// Package logging configures the process-wide structured logger.
//
// Log operations, never operand values. Secret plaintext must never
// reach a log record. secret.Value enforces this via LogValue,
// but call sites still must not pass raw byte slices.
package logging

import (
	"io"
	"log/slog"
	"os"
)

// redactSensitiveKeys replaces the value of any attribute whose key
// names secret-bearing content, regardless of the value's type.
// secret.Value already redacts itself. This is a defense-in-depth
// backstop for a raw string or []byte logged under one of these keys
// by mistake. Group keys are left alone so only leaf attributes are
// affected.
func redactSensitiveKeys(_ []string, attr slog.Attr) slog.Attr {
	switch attr.Key {
	case "passphrase", "value", "plaintext", "identity", "secret", "password", "token":
		attr.Value = slog.StringValue("[REDACTED]")
	}

	return attr
}

// Options control how the logger is built.
type Options struct {
	// Verbose lowers the level from Warn to Debug.
	Verbose bool
	// JSON switches the handler from text to JSON.
	JSON bool
}

// New builds a logger writing to w.
func New(w io.Writer, opts Options) *slog.Logger {
	level := slog.LevelWarn
	if opts.Verbose {
		level = slog.LevelDebug
	}

	handlerOpts := &slog.HandlerOptions{Level: level, ReplaceAttr: redactSensitiveKeys}

	var handler slog.Handler
	if opts.JSON {
		handler = slog.NewJSONHandler(w, handlerOpts)
	} else {
		handler = slog.NewTextHandler(w, handlerOpts)
	}

	return slog.New(handler)
}

// Setup builds a logger on stderr and installs it as the slog default.
func Setup(opts Options) *slog.Logger {
	logger := New(os.Stderr, opts)
	slog.SetDefault(logger)

	return logger
}
