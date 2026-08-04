package cmd

import (
	"fmt"
	"io"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// wordmark is the figlet "small" rendering of SAFETYBOX. Pure ASCII on
// purpose: the previous quadrant-glyph banner rendered unevenly across
// monospace fonts, and these glyphs cannot.
const wordmark = ` ___   _   ___ ___ _______   _____  _____  __
/ __| /_\ | __| __|_   _\ \ / / _ )/ _ \ \/ /
\__ \/ _ \| _|| _|  | |  \ V /| _ \ (_) >  <
|___/_/ \_\_| |___| |_|   |_| |___/\___/_/\_\`

// Gradient stops for the banner, one per wordmark row, magenta at the
// top ramping to orange at the bottom. Red is held at FF so the ramp
// never dips through muddy browns, and green/blue move in equal steps
// so four rows band evenly.
const (
	bannerStopOne   lipgloss.Color = "#FF5FD2"
	bannerStopTwo   lipgloss.Color = "#FF6CAB"
	bannerStopThree lipgloss.Color = "#FF7A85"
	bannerStopFour  lipgloss.Color = "#FF875E"
)

// Artisan palette: headings in bold yellow, command names and flag
// specs in green. ANSI palette indexes rather than hex so themed
// terminals keep their own gold and green.
const (
	headingColor lipgloss.Color = "3"
	itemColor    lipgloss.Color = "2"
)

// bannerStops is the banner's row-to-color wiring: element i colors
// wordmark row i. It is the single wiring the renderer and the
// gradient tests share, so the order the tests pin is the order the
// banner renders. A function rather than a package var, because
// gochecknoglobals bars the var.
func bannerStops() []lipgloss.Color {
	return []lipgloss.Color{bannerStopOne, bannerStopTwo, bannerStopThree, bannerStopFour}
}

// helpStyles carries the lipgloss styles for one help render. A fresh
// set is built per invocation from the destination writer, so color
// capability follows where the output actually goes rather than
// os.Stdout, which tests replace with buffers.
type helpStyles struct {
	heading lipgloss.Style
	item    lipgloss.Style
	art     []lipgloss.Style
}

func newHelpStyles(w io.Writer) helpStyles {
	renderer := lipgloss.NewRenderer(w)

	stops := bannerStops()

	art := make([]lipgloss.Style, 0, len(stops))
	for _, stop := range stops {
		art = append(art, renderer.NewStyle().Foreground(stop))
	}

	return helpStyles{
		heading: renderer.NewStyle().Bold(true).Foreground(headingColor),
		item:    renderer.NewStyle().Foreground(itemColor),
		art:     art,
	}
}

// banner tints each wordmark row with its gradient stop. The index
// guard keeps a future extra row plain instead of panicking.
func (s helpStyles) banner() string {
	lines := strings.Split(wordmark, "\n")
	for i, line := range lines {
		if i < len(s.art) {
			lines[i] = s.art[i].Render(line)
		}
	}

	return strings.Join(lines, "\n")
}

// usageTemplate mirrors cobra's default usage template with headings,
// command cells, and flag blocks routed through the styling funcs.
// Under the Ascii profile every func returns its input unchanged, so
// piped output stays byte-identical to stock cobra. The Additional
// Commands condition wraps mid-action to stay inside the line-length
// limit. Newlines inside {{...}} are separators, never output, so
// rejoining it would change nothing but the lint result.
const usageTemplate = `{{heading "Usage:"}}{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

{{heading "Aliases:"}}
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

{{heading "Examples:"}}
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{heading "Available Commands:"}}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{cmdCell .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{heading .Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{cmdCell .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{heading "Additional Commands:"}}{{range $cmds}}{{if (and (eq .GroupID "")
  (or .IsAvailableCommand (eq .Name "help")))}}
  {{cmdCell .Name .NamePadding}} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{heading "Flags:"}}
{{flagBlock .LocalFlags.FlagUsages}}{{end}}{{if .HasAvailableInheritedFlags}}

{{heading "Global Flags:"}}
{{flagBlock .InheritedFlags.FlagUsages}}{{end}}{{if .HasHelpSubCommands}}

{{heading "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{cmdCell .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

// cmdCell pads the command name to cobra's computed column first and
// styles the padded cell second. The order matters: padding must be
// computed on plain text, because ANSI codes count toward string
// length while occupying no terminal columns.
func (s helpStyles) cmdCell(name string, padding int) string {
	return s.item.Render(fmt.Sprintf("%-*s", padding, name))
}

// flagBlock colors the spec segment of each pflag usage line. pflag
// aligns the block before this runs. Its Fprintln join guarantees at
// least three spaces between spec and description, and a spec never
// contains two adjacent spaces, so the first double space after the
// indent is the boundary. Wrapped continuation lines start with
// whitespace and no dash, so they pass through unstyled. Styling is
// the final step per segment on purpose: nothing may compute widths
// on a styled string.
func (s helpStyles) flagBlock(block string) string {
	lines := strings.Split(strings.TrimRightFunc(block, unicode.IsSpace), "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if !strings.HasPrefix(trimmed, "-") {
			continue
		}

		gap := strings.Index(trimmed, "  ")
		if gap < 0 {
			continue
		}

		indent := len(line) - len(trimmed)
		lines[i] = line[:indent] + s.item.Render(trimmed[:gap]) + trimmed[gap:]
	}

	return strings.Join(lines, "\n")
}

// renderUsage executes the styled usage template against w. The
// template is parsed per call with a func map bound to w's styles.
// That keeps every styling decision on the destination writer and
// keeps cobra's global template-func registry untouched, so repeated
// newRootCmd calls in tests cannot race on shared state.
func renderUsage(w io.Writer, target *cobra.Command) error {
	// InheritedFlags is the exported accessor that forces cobra's
	// persistent-flag merge. The stock help path gets that merge from
	// mergePersistentFlags, which is unexported, so a renderer that
	// bypasses it must trigger the merge itself. Without this, a direct
	// Usage or Help call outside Execute's flow drops "[flags]" from the
	// use line and can omit inherited flags entirely.
	_ = target.InheritedFlags()

	styles := newHelpStyles(w)

	funcs := template.FuncMap{
		"heading":   styles.heading.Render,
		"cmdCell":   styles.cmdCell,
		"flagBlock": styles.flagBlock,
	}

	parsed, err := template.New("usage").Funcs(funcs).Parse(usageTemplate)
	if err != nil {
		return fmt.Errorf("parse usage template: %w", err)
	}

	if err := parsed.Execute(w, target); err != nil {
		return fmt.Errorf("render usage: %w", err)
	}

	return nil
}

// displayName renders the command name as a product name for the
// help header: first rune titlecased. Titlecase rather than upper so
// a digraph first letter capitalizes the way one letter would. An
// empty or invalid-UTF-8 name passes through unchanged.
func displayName(name string) string {
	first, size := utf8.DecodeRuneInString(name)
	if first == utf8.RuneError && size <= 1 {
		return name
	}

	return string(unicode.ToTitle(first)) + name[size:]
}

// styledHelp replaces cobra's default help func. It renders usage
// straight to the command's out writer instead of going through
// UsageString, which buffers through a bytes.Buffer and would force
// the colorless profile even on a real terminal. The banner appears
// only on the root, mirroring where the old logo lived.
func styledHelp(target *cobra.Command, _ []string) {
	out := target.OutOrStdout()
	styles := newHelpStyles(out)

	if !target.HasParent() {
		_, _ = fmt.Fprintln(out, styles.banner())
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, displayName(target.Name())+" "+target.Version)
		_, _ = fmt.Fprintln(out)
	}

	long := target.Long
	if long == "" {
		long = target.Short
	}

	if long = strings.TrimRightFunc(long, unicode.IsSpace); long != "" {
		_, _ = fmt.Fprintln(out, long)
		_, _ = fmt.Fprintln(out)
	}

	if !target.Runnable() && !target.HasSubCommands() {
		return
	}

	if err := renderUsage(out, target); err != nil {
		target.PrintErrln(err)
	}
}

// styledUsage keeps the default usage func's writer choice: usage on
// error goes to the err writer. SilenceUsage keeps this path rare,
// but any direct Usage() caller still degrades to plain correctly.
func styledUsage(target *cobra.Command) error {
	return renderUsage(target.OutOrStderr(), target)
}
