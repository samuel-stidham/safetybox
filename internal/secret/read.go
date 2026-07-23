package secret

import (
	"errors"
	"fmt"
	"io"
)

// readChunk is the initial capacity of the read buffer and the extra
// headroom added on each growth.
const readChunk = 512

// ReadAllWiping reads all of r into a returned slice, zeroing each
// intermediate buffer it outgrows. io.ReadAll leaves those grown-past
// buffers on the heap unwiped, which for secret input means an unzeroed
// copy of the plaintext lingers until the garbage collector reuses it.
// On a read error the partial content is wiped and nil is returned, so
// a half-read secret never survives the failure. The caller owns the
// returned slice and should zero it after use.
//
// End of input is detected with errors.Is, so a reader that WRAPS
// io.EOF inside a genuine failure reads as a clean end of input. That
// is wider than io.ReadAll's bare comparison. Every current caller
// passes a file, a pipe, or a decrypt stream that returns io.EOF bare.
func ReadAllWiping(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, readChunk)

	for {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), cap(buf)+cap(buf)+readChunk)
			copy(grown, buf)
			wipe(buf)
			buf = grown
		}

		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]

		if err != nil {
			if errors.Is(err, io.EOF) {
				return buf, nil
			}

			wipe(buf)

			return nil, fmt.Errorf("read: %w", err)
		}
	}
}

func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
