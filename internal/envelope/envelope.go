// Package envelope seals secret values in age envelopes bound to their
// vault address and to the mutable metadata a read must verify.
//
// The plaintext inside every envelope starts with a small header. The
// header carries a version tag, the canonical address
// (api/v1/<name>/<version>), and the env name and expiry the secret
// carried when this version was written. [Open] verifies the address
// against the row the blob came from, and returns the bound env name
// and expiry so the caller can compare them to the plaintext columns.
// That binds ciphertext to its row and makes a plaintext-column edit
// detectable, as long as the writer holds the value. A holder of the
// public recipient can still re-seal a whole forged envelope, so this
// is tamper evidence for keyless writes, not authentication.
package envelope

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/samuel-stidham/safetybox/v3/internal/secret"

	"filippo.io/age"
)

// envelopeVersion tags the framed plaintext. A v1 vault had no tag and
// framed only the address. A v2 envelope always carries this tag, so a
// missing tag on a v2 read is a framing failure, which also blocks a
// downgrade to the older unbound frame.
const envelopeVersion = "sbx2"

// header line prefixes for the bound metadata.
const (
	envPrefix = "env:"
	expPrefix = "exp:"
)

// headerTerminator is the blank line that separates the header from the
// value. The header lines are all non-empty, so the first occurrence is
// always the real terminator.
const headerTerminator = "\n\n"

// Bound is the per-version metadata sealed into the envelope beside the
// value. Empty fields mean the secret had no env name or no expiry when
// the version was written.
type Bound struct {
	EnvName   string
	ExpiresAt string
}

// Seal encrypts value to recipient, binding it to address and to bound.
func Seal(recipient age.Recipient, address string, bound Bound, value secret.Value) ([]byte, error) {
	// Check the framed fields in a fixed order, so a newline is reported
	// against a deterministic field. A map range would randomize which
	// field is named when more than one carries a newline.
	for _, framed := range []struct{ label, field string }{
		{"address", address},
		{"env name", bound.EnvName},
		{"expiry", bound.ExpiresAt},
	} {
		if strings.ContainsRune(framed.field, '\n') {
			return nil, fmt.Errorf("seal %s: %s has a newline: %w", address, framed.label, ErrInvalidFrame)
		}
	}

	header := buildHeader(address, bound)

	var sealed bytes.Buffer

	writer, err := age.Encrypt(&sealed, recipient)
	if err != nil {
		return nil, fmt.Errorf("seal %s: %w", address, err)
	}

	if _, err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("seal %s: %w", address, err)
	}

	if _, err := writer.Write(value.Expose()); err != nil {
		return nil, fmt.Errorf("seal %s: %w", address, err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("seal %s: %w", address, err)
	}

	return sealed.Bytes(), nil
}

// buildHeader frames the version tag, address, and bound metadata,
// terminated by a blank line.
func buildHeader(address string, bound Bound) []byte {
	var header bytes.Buffer

	header.WriteString(envelopeVersion)
	header.WriteByte('\n')
	header.WriteString(address)
	header.WriteByte('\n')

	if bound.EnvName != "" {
		header.WriteString(envPrefix)
		header.WriteString(bound.EnvName)
		header.WriteByte('\n')
	}

	if bound.ExpiresAt != "" {
		header.WriteString(expPrefix)
		header.WriteString(bound.ExpiresAt)
		header.WriteByte('\n')
	}

	header.WriteByte('\n')

	return header.Bytes()
}

// Open decrypts blob with identity, verifies it is bound to address,
// and returns the value with the env name and expiry sealed into it.
// The caller compares those against the plaintext columns to detect a
// metadata edit. The header is stripped before the value is wrapped in
// a [secret.Value].
func Open(identity age.Identity, address string, blob []byte) (secret.Value, Bound, error) {
	reader, err := age.Decrypt(bytes.NewReader(blob), identity)
	if err != nil {
		return secret.Value{}, Bound{}, fmt.Errorf("open %s: %w: %w", address, ErrDecryptFailed, err)
	}

	// ReadAllWiping zeroes each buffer it outgrows, so the decrypted
	// plaintext leaves no unwiped copies the way io.ReadAll would.
	payload, err := secret.ReadAllWiping(reader)
	if err != nil {
		return secret.Value{}, Bound{}, fmt.Errorf("open %s: %w: %w", address, ErrDecryptFailed, err)
	}

	// The decrypted payload holds plaintext on every path, including the
	// mismatch refusals below where it is the wrong row's plaintext.
	// secret.New copies what it keeps, so wipe the original regardless.
	defer clear(payload)

	value, bound, err := parseFrame(address, payload)
	if err != nil {
		return secret.Value{}, Bound{}, err
	}

	return secret.New(value), bound, nil
}

// OpenLegacy decrypts a version 1 envelope, whose frame is the address,
// a newline, and the value, with no version tag and no bound metadata.
// It is used only by the format migration to read the old frame before
// re-sealing it into the current one. The returned value must be
// re-sealed with [Seal], which binds the metadata the migration passes.
func OpenLegacy(identity age.Identity, address string, blob []byte) (secret.Value, error) {
	reader, err := age.Decrypt(bytes.NewReader(blob), identity)
	if err != nil {
		return secret.Value{}, fmt.Errorf("open %s: %w: %w", address, ErrDecryptFailed, err)
	}

	payload, err := secret.ReadAllWiping(reader)
	if err != nil {
		return secret.Value{}, fmt.Errorf("open %s: %w: %w", address, ErrDecryptFailed, err)
	}

	defer clear(payload)

	embedded, value, found := bytes.Cut(payload, []byte("\n"))
	if !found || string(embedded) != address {
		return secret.Value{}, fmt.Errorf("open %s: %w", address, ErrAddressMismatch)
	}

	return secret.New(value), nil
}

// parseFrame splits the decrypted payload into its header and value,
// checks the version tag and address, and reads the bound metadata. A
// missing tag, a wrong address, or an unknown header line is a framing
// failure, reported as [ErrAddressMismatch] so the read path treats it
// as tampering.
func parseFrame(address string, payload []byte) ([]byte, Bound, error) {
	header, value, found := bytes.Cut(payload, []byte(headerTerminator))
	if !found {
		return nil, Bound{}, fmt.Errorf("open %s: no header terminator: %w", address, ErrAddressMismatch)
	}

	lines := bytes.Split(header, []byte("\n"))
	if len(lines) < 2 || string(lines[0]) != envelopeVersion {
		return nil, Bound{}, fmt.Errorf("open %s: not a v2 envelope: %w", address, ErrAddressMismatch)
	}

	if string(lines[1]) != address {
		return nil, Bound{}, fmt.Errorf("open %s: %w", address, ErrAddressMismatch)
	}

	var bound Bound

	for _, line := range lines[2:] {
		switch {
		case bytes.HasPrefix(line, []byte(envPrefix)):
			bound.EnvName = string(line[len(envPrefix):])
		case bytes.HasPrefix(line, []byte(expPrefix)):
			bound.ExpiresAt = string(line[len(expPrefix):])
		default:
			return nil, Bound{}, fmt.Errorf("open %s: unknown header line: %w", address, ErrAddressMismatch)
		}
	}

	return value, bound, nil
}
