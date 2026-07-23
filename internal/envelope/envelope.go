// Package envelope seals secret values in age envelopes bound to
// their vault address.
//
// The plaintext inside every envelope is prefixed with its canonical
// address (api/v1/<name>/<version>) and a newline. [Open] verifies the
// embedded address matches the row the blob was read from, which
// binds ciphertext to its row and defeats envelope swapping.
package envelope

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/samuel-stidham/safetybox/v2/internal/secret"

	"filippo.io/age"
)

// addressSeparator terminates the embedded address. Addresses must
// never contain it.
const addressSeparator = '\n'

// Seal encrypts value to recipient, binding it to address.
func Seal(recipient age.Recipient, address string, value secret.Value) ([]byte, error) {
	if strings.ContainsRune(address, addressSeparator) {
		return nil, fmt.Errorf("seal %q: %w", address, ErrInvalidAddress)
	}

	var sealed bytes.Buffer

	writer, err := age.Encrypt(&sealed, recipient)
	if err != nil {
		return nil, fmt.Errorf("seal %s: %w", address, err)
	}

	if _, err := writer.Write([]byte(address)); err != nil {
		return nil, fmt.Errorf("seal %s: %w", address, err)
	}

	if _, err := writer.Write([]byte{addressSeparator}); err != nil {
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

// Open decrypts blob with identity and verifies it is bound to
// address. The embedded address is stripped before the plaintext is
// wrapped in a [secret.Value].
func Open(identity age.Identity, address string, blob []byte) (secret.Value, error) {
	reader, err := age.Decrypt(bytes.NewReader(blob), identity)
	if err != nil {
		return secret.Value{}, fmt.Errorf("open %s: %w: %w", address, ErrDecryptFailed, err)
	}

	// ReadAllWiping zeroes each buffer it outgrows, so the decrypted
	// plaintext leaves no unzeroed intermediate copies on the heap the
	// way io.ReadAll's growth would.
	payload, err := secret.ReadAllWiping(reader)
	if err != nil {
		return secret.Value{}, fmt.Errorf("open %s: %w: %w", address, ErrDecryptFailed, err)
	}

	// The decrypted payload holds plaintext on every path, including
	// the address-mismatch refusal below where it is the wrong row's
	// plaintext. secret.New copies what it keeps, so wipe the original
	// once this returns regardless of outcome.
	defer clear(payload)

	separator := bytes.IndexByte(payload, addressSeparator)
	if separator < 0 {
		return secret.Value{}, fmt.Errorf("open %s: no embedded address: %w", address, ErrAddressMismatch)
	}

	if string(payload[:separator]) != address {
		return secret.Value{}, fmt.Errorf("open %s: %w", address, ErrAddressMismatch)
	}

	return secret.New(payload[separator+1:]), nil
}
