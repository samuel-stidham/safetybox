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
// a half-read secret never survives the failure. On success the unused
// capacity of the returned slice is wiped, so scratch a reader may have
// left past its reported count does not survive. The caller owns the
// returned content and should zero it after use.
//
// End of input is exactly a bare io.EOF, matching io.ReadAll. An error
// that merely wraps io.EOF is a genuine failure, and treating it as a
// clean end would silently hand back truncated secret data.
func ReadAllWiping(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, readChunk)

	for {
		if len(buf) == cap(buf) {
			newCap := cap(buf) + cap(buf) + readChunk
			if newCap <= cap(buf) {
				// The growth overflowed int, which takes an input larger
				// than any machine can hold. Fail cleanly rather than let
				// make panic on a negative capacity.
				wipe(buf)

				return nil, errors.New("read: input too large")
			}

			grown := make([]byte, len(buf), newCap)
			copy(grown, buf)
			wipe(buf)
			buf = grown
		}

		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]

		if err != nil {
			if err == io.EOF {
				// Wipe the unused tail, so scratch a reader may have left
				// past its reported count does not survive in the backing
				// array. The content stays intact.
				wipe(buf[len(buf):cap(buf)])

				return buf, nil
			}

			// Wipe the whole capacity, not just the content length. A
			// reader is allowed to scribble scratch into the rest of the
			// slice it was handed, past the n bytes it reports, and that
			// scratch could be secret material too.
			wipe(buf[:cap(buf)])

			return nil, fmt.Errorf("read: %w", err)
		}
	}
}

func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
