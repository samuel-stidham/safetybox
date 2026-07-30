package envelope

import "errors"

var (
	// ErrAddressMismatch means the address inside the envelope does
	// not match the row it was read from. Treat as tampering.
	ErrAddressMismatch = errors.New("envelope address mismatch")
	// ErrDecryptFailed means age could not open the envelope.
	ErrDecryptFailed = errors.New("envelope decrypt failed")
	// ErrLegacyEnvelope means the payload decrypted cleanly but carries
	// the version 1 frame, which has no version tag and no bound
	// metadata. It accompanies ErrAddressMismatch so existing callers
	// still see a refusal, while a caller that cares can tell a stranded
	// legacy row from real tampering. The usual cause is an older
	// safetybox writing to a vault that migrate had already upgraded.
	ErrLegacyEnvelope = errors.New("envelope is in the superseded version 1 format")
	// ErrInvalidFrame means a field bound into the envelope, such as the
	// address, env name, or expiry, cannot be framed, for example
	// because it contains a newline.
	ErrInvalidFrame = errors.New("invalid envelope frame")
)
