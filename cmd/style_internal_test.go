package cmd

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// artRowOne and artRowFour pin the first and last rows of the figlet
// wordmark. Row four is a raw string because it is mostly backslashes.
const (
	artRowOne  = ` ___   _   ___ ___ _______   _____  _____  __`
	artRowFour = `|___/_/ \_\_| |___| |_|   |_| |___/\___/_/\_\`
)

// runHelp runs the root command with args against a buffer and returns
// what landed on the out writer.
func runHelp(t *testing.T, args ...string) string {
	t.Helper()

	root := newRootCmd("1.2.3-test")
	root.SetArgs(args)

	var out bytes.Buffer

	root.SetOut(&out)
	root.SetErr(io.Discard)

	require.NoError(t, root.Execute())

	return out.String()
}

func TestRootHelpShowsBannerPlain(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "0")

	out := runHelp(t, "--help")

	assert.Contains(t, out, artRowOne)
	assert.Contains(t, out, artRowFour)
	assert.Contains(t, out, "Safetybox 1.2.3-test")
	assert.Contains(t, out, "Safetybox is a CLI-first secrets manager.")
	assert.Contains(t, out, "Usage:\n  safetybox [command]")
	assert.Contains(t, out, "Available Commands:")
	assert.Contains(t, out, "reveal")
	assert.Contains(t, out, "rekey")
	assert.Contains(t, out, "Flags:")
	assert.Contains(t, out, "--vault string")
	assert.Contains(t, out, "-v, --verbose")
	assert.Contains(t, out, "--passphrase-file string")
	assert.Contains(t, out, `Use "safetybox [command] --help" for more information about a command.`)
	assert.NotContains(t, out, "\x1b")
}

func TestBareRootPrintsHelp(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "0")

	out := runHelp(t)

	assert.Contains(t, out, artRowOne)
	assert.Contains(t, out, "Usage:")
}

func TestSubcommandHelpPlain(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "0")

	out := runHelp(t, "set", "--help")

	assert.Contains(t, out, "Usage:")
	assert.Contains(t, out, "safetybox set")
	assert.Contains(t, out, "Global Flags:")
	assert.Contains(t, out, "--vault string")
	assert.NotContains(t, out, artRowOne)
	assert.NotContains(t, out, "\x1b")
}

func TestHelpColorForced(t *testing.T) {
	// NO_COLOR beats CLICOLOR_FORCE in termenv, so both have to be
	// pinned for the forced-color profile to survive an inherited
	// NO_COLOR in the caller's environment.
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")

	out := runHelp(t, "--help")

	assert.Contains(t, out, "\x1b[")
	assert.Contains(t, out, "Usage:")
	assert.Contains(t, out, artRowOne)
}

// TestDisplayName pins rune-aware capitalization: a multi-byte first
// rune must titlecase as one rune, never byte-by-byte, and empty or
// invalid input passes through unchanged.
func TestDisplayName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "ascii", input: "safetybox", want: "Safetybox"},
		{name: "empty", input: "", want: ""},
		{name: "multi-byte first rune", input: "ñame", want: "Ñame"},
		{name: "already capitalized", input: "Safetybox", want: "Safetybox"},
		{name: "invalid leading byte", input: "\xffbox", want: "\xffbox"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, displayName(testCase.input))
		})
	}
}

// TestBannerGradientOrder pins the row-to-stop wiring under forced
// color. termenv caps a forced non-TTY writer at the 16-color ANSI
// profile. The four hex stops downsample to two codes there: rows one
// and two land on bright magenta, rows three and four on bright red.
// The per-row equality against styles built on bannerStops() pins
// that banner() consumes the shared wiring in index order, and it
// catches any cross-band mis-wiring, including a full reversal. A
// same-band adjacent swap inside bannerStops() is invisible at this
// profile. TestBannerGradientRampDirection catches every such
// reorder, because the ramp it pins is strictly monotonic.
// The distinctness floor of two proves the profile is actually
// coloring, so the order assertions never pass vacuously. COLORTERM
// and TERM stay pinned as an upgrade path: a future termenv that
// promotes forced buffers renders more stops distinct, and this test
// only tightens.
func TestBannerGradientOrder(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")
	t.Setenv("COLORTERM", "truecolor")
	t.Setenv("TERM", "xterm-256color")

	var buf bytes.Buffer

	styles := newHelpStyles(&buf)
	lines := strings.Split(styles.banner(), "\n")

	renderer := lipgloss.NewRenderer(&buf)
	stops := bannerStops()
	rows := strings.Split(wordmark, "\n")

	require.Len(t, rows, len(stops))
	require.Len(t, lines, len(stops))

	rendered := make(map[string]struct{}, len(stops))

	for i, stop := range stops {
		want := renderer.NewStyle().Foreground(stop).Render(rows[i])

		assert.Contains(t, want, "\x1b[", "stop %d must render color under the forced profile", i+1)
		assert.Equal(t, want, lines[i], "banner row %d must carry gradient stop %d", i+1, i+1)

		rendered[renderer.NewStyle().Foreground(stop).Render("probe")] = struct{}{}
	}

	assert.GreaterOrEqual(t, len(rendered), 2, "the forced profile must keep at least two bands distinct")
}

// TestBannerGradientRampDirection pins the value sequence of
// bannerStops(), the same wiring the renderer consumes: red held at
// FF, green strictly climbing, blue strictly falling, top to bottom.
// Strict monotonicity means swapping any two stops, whether constant
// values or slice positions, reverses a channel somewhere and fails
// here. That covers the same-band swaps the ANSI-16 render-order
// test cannot see. Position-to-name identity is deliberately not
// asserted: swapping two constants' names and values together
// renders byte-identically, so that assertion would pin naming and
// never behavior.
func TestBannerGradientRampDirection(t *testing.T) {
	stops := bannerStops()

	type rgb struct{ r, g, b uint64 }

	channels := make([]rgb, 0, len(stops))

	for _, stop := range stops {
		hex := string(stop)
		require.Len(t, hex, 7)
		require.Equal(t, uint8('#'), hex[0])

		red, err := strconv.ParseUint(hex[1:3], 16, 8)
		require.NoError(t, err)

		green, err := strconv.ParseUint(hex[3:5], 16, 8)
		require.NoError(t, err)

		blue, err := strconv.ParseUint(hex[5:7], 16, 8)
		require.NoError(t, err)

		channels = append(channels, rgb{r: red, g: green, b: blue})
	}

	for i, channel := range channels {
		assert.EqualValues(t, 0xFF, channel.r, "stop %d must hold red at FF", i+1)

		if i == 0 {
			continue
		}

		assert.Greater(t, channel.g, channels[i-1].g, "green must climb toward orange")
		assert.Less(t, channel.b, channels[i-1].b, "blue must fall toward orange")
	}
}

// TestFlagBlockStylesOnlyTheSpec pins flagBlock's segmentation under
// forced color: indent and description stay plain, only the spec is
// styled, and continuation lines pass through untouched. Expected
// segments render through the same item style, so no escape code is
// hardcoded.
func TestFlagBlockStylesOnlyTheSpec(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")

	var buf bytes.Buffer

	styles := newHelpStyles(&buf)

	block := "      --vault string   path to the vault database\n" +
		"                       wrapped continuation line\n" +
		"  -v, --verbose        enable debug logging\n"

	got := styles.flagBlock(block)

	want := "      " + styles.item.Render("--vault string") + "   path to the vault database\n" +
		"                       wrapped continuation line\n" +
		"  " + styles.item.Render("-v, --verbose") + "        enable debug logging"

	assert.Equal(t, want, got)
	assert.Contains(t, got, "\x1b[", "forced color must reach the spec segments")
}

// TestSubcommandHelpMatchesStockCobra pins byte parity between the
// styled help path and cobra's stock rendering for every registered
// subcommand under the colorless profile. usageTemplate is a
// maintained mirror of cobra's default, so a cobra upgrade that moves
// the default layout fails here first. The root is excluded by
// design: its styled help adds the banner and version header that
// stock cobra never prints.
func TestSubcommandHelpMatchesStockCobra(t *testing.T) {
	t.Setenv("CLICOLOR_FORCE", "0")

	render := func(t *testing.T, stock bool, args ...string) string {
		t.Helper()

		root := newRootCmd("1.2.3-test")
		if stock {
			// Nil restores cobra's default help and usage funcs, which
			// newRootCmd replaced with the styled pair.
			root.SetHelpFunc(nil)
			root.SetUsageFunc(nil)
		}

		root.SetArgs(args)

		var out bytes.Buffer

		root.SetOut(&out)
		root.SetErr(io.Discard)

		require.NoError(t, root.Execute())

		return out.String()
	}

	// Execute adds the help and completion commands late, inside
	// ExecuteC, so a bare Commands() walk on a fresh root misses them.
	// These two Init calls mirror ExecuteC's own initialization, so the
	// walk covers every top-level command a user can ask help for.
	enumRoot := newRootCmd("1.2.3-test")
	enumRoot.InitDefaultHelpCmd()
	enumRoot.InitDefaultCompletionCmd()

	for _, sub := range enumRoot.Commands() {
		t.Run(sub.Name(), func(t *testing.T) {
			styled := render(t, false, sub.Name(), "--help")
			plain := render(t, true, sub.Name(), "--help")

			assert.Equal(t, plain, styled)
		})
	}
}
