package envelope

import "errors"

var (
	// ErrAddressMismatch means the address inside the envelope does
	// not match the row it was read from. Treat as tampering.
	ErrAddressMismatch = errors.New("envelope address mismatch")
	// ErrDecryptFailed means age could not open the envelope.
	ErrDecryptFailed = errors.New("envelope decrypt failed")
	// ErrInvalidFrame means a field bound into the envelope, such as the
	// address, env name, or expiry, cannot be framed, for example
	// because it contains a newline.
	ErrInvalidFrame = errors.New("invalid envelope frame")
)
