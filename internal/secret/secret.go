// Package secret defines [Value], the only type in this codebase
// allowed to hold plaintext secret bytes.
//
// The bytes are unexported and held behind a pointer. Plaintext exits
// only through [Value.Expose]. Every fmt verb is intercepted by
// [Value.Format], and JSON and slog are overridden, so a directly
// rendered Value always redacts. A Value stored in another struct's
// unexported field cannot be method-dispatched by fmt reflection, so
// the pointer indirection ensures that path reflects an address rather
// than the bytes. Never add another exit and never move this type into
// a shared flat package. The package boundary keeps the redaction total.
package secret

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[REDACTED]"

// Value holds plaintext secret bytes behind a redacting wall. The
// bytes sit behind a pointer so that fmt reflecting into an
// unexported Value field prints the pointer, never the plaintext.
type Value struct {
	held *[]byte
}

// New copies plaintext into a Value. The caller keeps ownership
// of the input slice and should zero it when possible.
func New(plaintext []byte) Value {
	held := make([]byte, len(plaintext))
	copy(held, plaintext)

	return Value{held: &held}
}

// Expose returns the plaintext bytes. This is the ONLY plaintext exit.
// Call it as late as possible. The call sites are the reveal output,
// the exec environment, the envelope seal path, and the init
// self-test.
//
// The returned slice aliases the Value's internal storage. Callers
// must not retain it past the Value's lifetime or mutate it, because
// copies of a Value share one backing array. Use [Value.Destroy] to
// wipe the storage once the plaintext is no longer needed.
func (v Value) Expose() []byte {
	if v.held == nil {
		return nil
	}

	return *v.held
}

// Destroy zeroes the held plaintext and drops the reference. It cuts
// the in-memory lifetime of a decrypted value down from the whole
// process run to the span the caller actually needs it. Copies of a
// Value share one backing array through a single pointer, so one
// Destroy wipes every copy. It is safe to call more than once, and
// Expose returns nil afterward. This does not reach Go strings already
// produced by Expose, which are immutable and outside this control.
func (v Value) Destroy() {
	if v.held == nil {
		return
	}

	for i := range *v.held {
		(*v.held)[i] = 0
	}

	*v.held = nil
}

// Format implements fmt.Formatter so that EVERY verb redacts,
// including numeric verbs like %d and %c that bypass fmt.Stringer.
func (v Value) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redacted)
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
