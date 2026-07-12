// Package secret defines Value, the only type in this codebase
// allowed to hold plaintext secret bytes.
//
// The bytes are unexported. Plaintext exits only through Expose.
// Every other rendering path (fmt, JSON, slog) is overridden to return
// a redaction marker. Never add another exit and never move this type
// into a shared flat package. The package boundary is what makes the
// redaction compiler-enforced.
package secret

import "log/slog"

const redacted = "[REDACTED]"

// Value holds plaintext secret bytes behind a redacting wall.
type Value struct {
	bytes []byte
}

// New copies plaintext into a Value. The caller keeps ownership
// of the input slice and should zero it when possible.
func New(plaintext []byte) Value {
	held := make([]byte, len(plaintext))
	copy(held, plaintext)

	return Value{bytes: held}
}

// Expose returns the plaintext bytes. This is the ONLY plaintext exit.
// Call it as late as possible. The call sites are the reveal output,
// the exec environment, the envelope seal path, and the init
// self-test.
func (v Value) Expose() []byte {
	return v.bytes
}

// String implements fmt.Stringer and always redacts.
func (v Value) String() string {
	return redacted
}

// GoString implements fmt.GoStringer so %#v also redacts.
func (v Value) GoString() string {
	return redacted
}

// MarshalJSON always renders the redaction marker.
func (v Value) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

// LogValue implements slog.LogValuer so log records always redact.
func (v Value) LogValue() slog.Value {
	return slog.StringValue(redacted)
}
