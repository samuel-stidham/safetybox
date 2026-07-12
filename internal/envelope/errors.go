package envelope

import "errors"

var (
	// ErrAddressMismatch means the address inside the envelope does
	// not match the row it was read from. Treat as tampering.
	ErrAddressMismatch = errors.New("envelope address mismatch")
	// ErrDecryptFailed means age could not open the envelope.
	ErrDecryptFailed = errors.New("envelope decrypt failed")
	// ErrInvalidAddress means the address cannot be framed inside an
	// envelope, for example because it contains a newline.
	ErrInvalidAddress = errors.New("invalid envelope address")
)
