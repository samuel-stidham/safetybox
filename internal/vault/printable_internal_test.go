package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPrintableName pins that a name the grammar allows prints as it is,
// and anything else is quoted with its control bytes escaped.
func TestPrintableName(t *testing.T) {
	for _, testCase := range []struct {
		name string
		want string
	}{
		{name: "api/a", want: "api/a"},
		{name: "api/v1/some.name_with-marks", want: "api/v1/some.name_with-marks"},
		{name: "api/a\nINFO fake forged line\x1b[2K", want: `"api/a\nINFO fake forged line\x1b[2K"`},
		{name: "has space", want: `"has space"`},
		{name: "", want: `""`},
	} {
		assert.Equal(t, testCase.want, printableName(testCase.name))
	}
}
